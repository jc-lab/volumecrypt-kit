//! `vck-sample-driver`: the JVCK sample kernel driver (builds to a `.sys`).
//!
//! Wires the sample `VckVolumeProvider` into the `vck-driver` framework.
#![no_std]
#![allow(non_snake_case)]

extern crate alloc;

mod provider;

pub use provider::VckVolumeProvider;

use core::ffi::c_void;
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
    filter::{detach_filter, handle_filter_irp},
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

// The metadata/crypto path uses a large stack frame; run IOCTL dispatch on an
// expanded kernel stack so the (deep) storage stack below us has headroom.
const DISPATCH_STACK_SIZE: usize = 0x8000; // 32 KiB

extern "system" {
    fn KeExpandKernelStackAndCallout(
        callout: Option<unsafe extern "C" fn(*mut c_void)>,
        parameter: *mut c_void,
        size: usize,
    ) -> NTSTATUS;
}

/// Context passed to the expanded-stack dispatch callout.
struct ExpandCtx {
    ioctl_code: u32,
    requestor_mode: RequestorMode,
    input_ptr: *const u8,
    input_len: usize,
    result: Option<vck_driver::VckResult<alloc::vec::Vec<u8>>>,
}

/// Runs the actual IOCTL dispatch on the expanded stack.
unsafe extern "C" fn dispatch_callout(parameter: *mut c_void) {
    let cx = &mut *(parameter as *mut ExpandCtx);
    let input: &[u8] = if cx.input_len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(cx.input_ptr, cx.input_len)
    };
    let auth_ctx = IoctlAuthContext {
        ioctl_code: cx.ioctl_code,
        requestor_mode: cx.requestor_mode,
        requestor_token: None,
    };
    cx.result = Some(dispatch_ioctl(&PROVIDER, &REGISTRY, &auth_ctx, input));
}

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

    // Register AddDevice so PnP calls us before any FSD mounts on a volume.
    // This allows attaching the filter BELOW the FSD (correct position for
    // transparent encryption), without the lock/dismount dance.
    (*driver.DriverExtension).AddDevice = Some(add_device);

    driver.DriverUnload = Some(driver_unload);
    // Every device this driver owns (control + filters) shares one dispatcher
    // that routes by the device-extension kind.
    for slot in driver.MajorFunction.iter_mut() {
        *slot = Some(dispatch_any);
    }

    STATUS_SUCCESS
}

/// PnP AddDevice callback. Called for every volume device before any FSD mounts.
///
/// Attaches an unbound (pass-through) filter to the physical device object so that
/// when IOCTL_JVCK_PREPARE later runs for this volume, it can use `filter_bind_volume`
/// to activate encryption without needing to do lock/dismount. NTFS mounts above
/// our filter → correct transparent-encryption stack.
unsafe extern "C" fn add_device(driver: PDRIVER_OBJECT, pdo: PDEVICE_OBJECT) -> NTSTATUS {
    vck_driver::driver_println!("add_device: pdo={:p}", pdo);

    // Attach an UNBOUND filter to the physical device object before any FSD mounts.
    // The filter has volume=NULL → all IRPs pass through transparently.
    // IOCTL_JVCK_PREPARE will later find this filter by walking the device stack
    // and bind it to a volume (activating encryption).
    match vck_driver::filter::attach_filter_to_raw_device(driver, pdo) {
        Ok((filter_do, lower_do)) => {
            vck_driver::driver_println!(
                "add_device: filter attached filter={:p} lower={:p}", filter_do, lower_do
            );
            // Note: filter is unbound (volume=NULL). PREPARE walks the stack to find it.
            STATUS_SUCCESS
        }
        Err(err) => {
            vck_driver::driver_println!("add_device: attach failed: {}", err);
            STATUS_SUCCESS // Non-fatal: device still works without filter
        }
    }
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
        // Size-query rewrite (hide metadata) + read/write offset shift. AES-XTS
        // in-flight crypto will be layered on inside the filter handler.
        return handle_filter_irp(device_object, irp);
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

    // Run the dispatch on an expanded kernel stack (the metadata/crypto path is
    // stack-hungry and calls down the storage stack). Fall back to the current
    // stack if expansion fails.
    let mut ex = ExpandCtx {
        ioctl_code,
        requestor_mode,
        input_ptr: input.as_ptr(),
        input_len: input.len(),
        result: None,
    };
    let callout_status = unsafe {
        KeExpandKernelStackAndCallout(
            Some(dispatch_callout),
            (&mut ex as *mut ExpandCtx).cast::<c_void>(),
            DISPATCH_STACK_SIZE,
        )
    };
    let dispatch_result = if callout_status >= 0 {
        ex.result
            .take()
            .unwrap_or_else(|| Err(vck_driver::VckError::Io("dispatch callout did not run".into())))
    } else {
        let auth_ctx = IoctlAuthContext {
            ioctl_code,
            requestor_mode,
            requestor_token: None,
        };
        dispatch_ioctl(&PROVIDER, &REGISTRY, &auth_ctx, input)
    };

    match dispatch_result {
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
