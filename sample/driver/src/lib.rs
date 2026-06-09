//! `vck-sample-driver`: the JVCK sample kernel driver (builds to a `.sys`).
//!
//! Wires the sample `VckVolumeProvider` into the `vck-driver` framework.
#![no_std]
#![allow(non_snake_case)]

extern crate alloc;

mod provider;

pub use provider::VckVolumeProvider;

use core::panic::PanicInfo;

use spin::{Lazy, Mutex};
use wdk_alloc::WdkAllocator;
use wdk_sys::{
    ntddk::IofCompleteRequest, CCHAR, DRIVER_OBJECT, IO_NO_INCREMENT, IRP_MJ_CLEANUP,
    IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, NTSTATUS, PDEVICE_OBJECT, PDRIVER_OBJECT,
    PIRP, PIO_STACK_LOCATION, PCUNICODE_STRING, _MODE,
};
use vck_driver::{
    device::{ControlDevice, DeviceExtension, DEVICE_KIND_FILTER},
    filter::{detach_filter, pass_through},
    ioctl::dispatch_ioctl,
    provider::{IoctlAuthContext, RequestorMode},
    SweepWorker, VolumeAttachRegistry,
};

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

static CONTROL_DEVICE: Mutex<Option<ControlDevice>> = Mutex::new(None);
static REGISTRY: Lazy<VolumeAttachRegistry> = Lazy::new(VolumeAttachRegistry::new);
static SWEEP: Mutex<Option<SweepWorker>> = Mutex::new(None);
static PROVIDER: VckVolumeProvider = VckVolumeProvider;

const STATUS_SUCCESS: NTSTATUS = 0;
const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC000_0001u32 as i32;
const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000Du32 as i32;
const STATUS_INVALID_DEVICE_REQUEST: NTSTATUS = 0xC000_0010u32 as i32;
const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023u32 as i32;

/// Kernel driver entry point.
///
/// # Safety
/// Called by the kernel with valid driver object / registry path pointers.
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(
    driver: *mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let _ = registry_path;
    let driver = match driver.as_mut() {
        Some(driver) => driver,
        None => return STATUS_INVALID_PARAMETER,
    };

    match ControlDevice::create(driver as *mut DRIVER_OBJECT) {
        Ok(control_device) => {
            *CONTROL_DEVICE.lock() = Some(control_device);
        }
        Err(err) => {
            vck_driver::driver_println!("sample-driver: control device create failed: {}", err);
            return STATUS_UNSUCCESSFUL;
        }
    }

    // Start the background encrypt/decrypt sweep worker.
    match SweepWorker::start(&REGISTRY) {
        Ok(worker) => *SWEEP.lock() = Some(worker),
        Err(err) => {
            vck_driver::driver_println!("sample-driver: sweep worker start failed: {}", err);
            if let Some(control_device) = CONTROL_DEVICE.lock().take() {
                let _ = control_device.destroy();
            }
            return STATUS_UNSUCCESSFUL;
        }
    }

    // Needed by IOCTL_JVCK_ATTACH to create filter device objects.
    REGISTRY.set_driver_object(driver as *mut DRIVER_OBJECT);

    driver.DriverUnload = Some(driver_unload);
    // Every device this driver owns (control + filters) shares one dispatcher
    // that routes by the device-extension kind.
    for slot in driver.MajorFunction.iter_mut() {
        *slot = Some(dispatch_any);
    }

    STATUS_SUCCESS
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    vck_driver::debug::panic_print(info)
}

unsafe extern "C" fn driver_unload(_driver: PDRIVER_OBJECT) {
    // Stop the sweep worker first so it no longer touches the registry.
    if let Some(worker) = SWEEP.lock().take() {
        worker.stop();
    }

    // Detach any volume filters still attached, so no filter device object
    // outlives this driver's code.
    for volume in REGISTRY.all() {
        let filter_do = volume
            .filter_device
            .swap(core::ptr::null_mut(), core::sync::atomic::Ordering::AcqRel);
        if !filter_do.is_null() {
            detach_filter(filter_do);
        }
        REGISTRY.remove(&volume.volume_path);
    }

    if let Some(control_device) = CONTROL_DEVICE.lock().take() {
        if let Err(err) = control_device.destroy() {
            vck_driver::driver_println!("sample-driver: control device destroy failed: {}", err);
        }
    }
}

/// Shared dispatcher for every device this driver owns. Filter devices forward
/// to the device below; the control device handles CREATE/CLOSE/CLEANUP and
/// DEVICE_CONTROL.
unsafe extern "C" fn dispatch_any(device_object: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    if device_object.is_null() || irp.is_null() {
        if !irp.is_null() {
            complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
        }
        return STATUS_INVALID_PARAMETER;
    }

    let ext = DeviceExtension::of(device_object);
    if ext.kind == DEVICE_KIND_FILTER {
        // Transparent pass-through for now; AES-XTS interception of READ/WRITE
        // will be layered on here.
        return pass_through(ext.lower_device, irp);
    }

    // Control device.
    let stack = current_stack_location(irp);
    let major = if stack.is_null() {
        u32::MAX
    } else {
        (*stack).MajorFunction as u32
    };
    match major {
        IRP_MJ_DEVICE_CONTROL => dispatch_device_control(device_object, irp),
        IRP_MJ_CREATE | IRP_MJ_CLOSE | IRP_MJ_CLEANUP => {
            complete_irp(irp, STATUS_SUCCESS, 0);
            STATUS_SUCCESS
        }
        _ => {
            complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

unsafe extern "C" fn dispatch_device_control(
    _device_object: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    if irp.is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    let stack = current_stack_location(irp);
    if stack.is_null() {
        complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }

    let params = unsafe { (*stack).Parameters.DeviceIoControl };
    let ioctl_code = params.IoControlCode;
    let input_len = params.InputBufferLength as usize;
    let output_len = params.OutputBufferLength as usize;
    let system_buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer as *mut u8 };

    let input = if input_len == 0 {
        &[][..]
    } else if system_buffer.is_null() {
        complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    } else {
        unsafe { core::slice::from_raw_parts(system_buffer.cast_const(), input_len) }
    };

    let requestor_mode = match unsafe { (*irp).RequestorMode } {
        mode if mode == _MODE::KernelMode as i8 => RequestorMode::Kernel,
        _ => RequestorMode::User,
    };

    let auth_ctx = IoctlAuthContext {
        ioctl_code,
        requestor_mode,
        requestor_token: None,
    };

    match dispatch_ioctl(&PROVIDER, &REGISTRY, &auth_ctx, input) {
        Ok(response) => {
            if response.len() > output_len {
                complete_irp(irp, STATUS_BUFFER_TOO_SMALL, 0);
                STATUS_BUFFER_TOO_SMALL
            } else {
                if !response.is_empty() {
                    if system_buffer.is_null() {
                        complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
                        return STATUS_INVALID_PARAMETER;
                    }
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            response.as_ptr(),
                            system_buffer,
                            response.len(),
                        );
                    }
                }
                complete_irp(irp, STATUS_SUCCESS, response.len());
                STATUS_SUCCESS
            }
        }
        Err(err) => {
            vck_driver::driver_println!(
                "sample-driver: ioctl 0x{:08x} failed: {}",
                ioctl_code,
                err
            );
            complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
            STATUS_UNSUCCESSFUL
        }
    }
}

unsafe fn current_stack_location(irp: PIRP) -> PIO_STACK_LOCATION {
    unsafe { (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation }
}

unsafe fn complete_irp(irp: PIRP, status: NTSTATUS, information: usize) {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = information as _;
        IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
    }
}
