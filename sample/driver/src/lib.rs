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
    IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, NTSTATUS, PDEVICE_OBJECT,
    PDRIVER_OBJECT, PIRP, PIO_STACK_LOCATION, PCUNICODE_STRING, _MODE,
};
use vck_driver::{
    device::ControlDevice,
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

    driver.DriverUnload = Some(driver_unload);
    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_CLEANUP as usize] = Some(dispatch_create_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch_device_control);

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
    if let Some(control_device) = CONTROL_DEVICE.lock().take() {
        if let Err(err) = control_device.destroy() {
            vck_driver::driver_println!("sample-driver: control device destroy failed: {}", err);
        }
    }
}

unsafe extern "C" fn dispatch_create_close(
    _device_object: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    complete_irp(irp, STATUS_SUCCESS, 0);
    STATUS_SUCCESS
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
