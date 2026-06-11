// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

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
    ntddk::{
        IoBuildDeviceIoControlRequest, IoGetRequestorProcess, IofCallDriver, IofCompleteRequest,
        KeInitializeEvent, KeWaitForSingleObject,
    },
    CCHAR, DRIVER_OBJECT, IO_NO_INCREMENT, IO_STATUS_BLOCK, IRP_MJ_CLEANUP, IRP_MJ_CLOSE,
    IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_SHUTDOWN, KEVENT, NTSTATUS, PDEVICE_OBJECT,
    PDRIVER_OBJECT, PIRP, PIO_STACK_LOCATION, PCUNICODE_STRING,
    _EVENT_TYPE::NotificationEvent, _KWAIT_REASON::Executive, _MODE,
};
use vck_driver::{
    device::{ControlDevice, DeviceExtension, DEVICE_KIND_FILTER},
    filter::handle_filter_irp,
    ioctl::codes::{IOCTL_VCK_DETACH_ALL_VOLUMES, IOCTL_VCK_PAUSE_OS_VOLUME},
    ioctl::dispatch_ioctl,
    provider::{AccessToken, IoctlAuthContext, RequestorMode},
    VolumeAttachRegistry,
};
use vck_sample_common::VckHandoverPayload;

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

static CONTROL_DEVICE: Mutex<Option<ControlDevice>> = Mutex::new(None);
static REGISTRY: Lazy<VolumeAttachRegistry> = Lazy::new(VolumeAttachRegistry::new);
static PROVIDER: VckVolumeProvider = VckVolumeProvider;

const STATUS_SUCCESS: NTSTATUS = 0;
const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC000_0001u32 as i32;
const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000Du32 as i32;
const STATUS_INVALID_DEVICE_REQUEST: NTSTATUS = 0xC000_0010u32 as i32;
const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023u32 as i32;
const STATUS_PENDING: NTSTATUS = 0x0000_0103;

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
    /// Borrowed requestor token (null when none); owned by the outer handler
    /// frame, which outlives this synchronous callout.
    requestor_token: *const AccessToken,
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
        requestor_token: cx.requestor_token.as_ref(),
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
    vck_driver::driver_println!("DriverEntry: vck-sample-driver loading");
    let driver = match driver.as_mut() {
        Some(driver) => driver,
        None => return STATUS_INVALID_PARAMETER,
    };

    match ControlDevice::create(
        driver as *mut DRIVER_OBJECT,
        &provider::control_device_security(),
    ) {
        Ok(control_device) => {
            *CONTROL_DEVICE.lock() = Some(control_device);
        }
        Err(err) => {
            vck_driver::driver_println!("sample-driver: control device create failed: {}", err);
            return STATUS_UNSUCCESSFUL;
        }
    }

    // IO + background sweep are handled by per-volume threads, created at bind
    // (filter_bind_volume / filter_rebind_volume) and stopped at detach. No
    // global IO/sweep threads are needed.

    // Needed by IOCTL_JVCK_ATTACH to create filter device objects.
    REGISTRY.set_driver_object(driver as *mut DRIVER_OBJECT);

    // Publish the registry so the filter's PnP work item (a C callback that only
    // receives a device object) can reach it to auto-attach the OS volume.
    vck_driver::set_global_registry(&*REGISTRY);

    // Best-effort: read the boot ACPI handover (`VCKD` table) published by the
    // UEFI loader. Absent (NotFound) when booting without the loader — the OS
    // volume auto-attach path then stays dormant and data volumes are unaffected.
    match vck_driver::handover::read_handover::<VckHandoverPayload>() {
        Ok(payload) => {
            vck_driver::driver_println!(
                "DriverEntry: loader handover present, OS partition {}",
                payload.partition_guid
            );
            REGISTRY.set_handover(vck_driver::HandoverInfo {
                partition_guid: payload.partition_guid,
                vmk: payload.vmk,
            });
        }
        Err(err) => {
            vck_driver::driver_println!("DriverEntry: no ACPI handover ({})", err);
        }
    }

    // Register AddDevice so PnP calls us before any FSD mounts on a volume.
    // This allows attaching the filter BELOW the FSD (correct position for
    // transparent encryption), without the lock/dismount dance.
    (*driver.DriverExtension).AddDevice = Some(add_device);

    driver.DriverUnload = Some(driver_unload);
    // Every device this driver owns (control + filters) shares one dispatcher.
    for slot in driver.MajorFunction.iter_mut() {
        *slot = Some(dispatch_any);
    }

    // IRP_MJ_SHUTDOWN is routed via dispatch_any (all major functions are set).
    // DriverUnload also handles clean shutdown.

    STATUS_SUCCESS
}

/// PnP AddDevice callback. Called for every volume device before any FSD mounts.
///
/// Attaches an unbound (pass-through) filter to the physical device object so that
/// when IOCTL_JVCK_PREPARE later runs for this volume, it can use `filter_bind_volume`
/// to activate encryption without needing to do lock/dismount. NTFS mounts above
/// our filter → correct transparent-encryption stack.
unsafe extern "C" fn add_device(driver: PDRIVER_OBJECT, pdo: PDEVICE_OBJECT) -> NTSTATUS {
    use core::ffi::c_void;

    // Query the PDO object name to identify which volume this is for.
    let pdo_name: alloc::string::String = {
        let mut buf = [0u8; 256];
        let mut ret_len: u32 = 0;
        let st = wdk_sys::ntddk::ObQueryNameString(
            pdo.cast::<c_void>(), buf.as_mut_ptr().cast(), 256, &mut ret_len,
        );
        if st >= 0 {
            let name_len = u16::from_le_bytes([buf[0], buf[1]]) as usize / 2;
            let name_ptr = usize::from_le_bytes(buf[8..16].try_into().unwrap_or([0;8]));
            if name_len > 0 && name_ptr != 0 {
                let chars = core::slice::from_raw_parts(name_ptr as *const u16, name_len.min(64));
                let mut s = alloc::string::String::new();
                for &c in chars { if c >= 0x20 && c < 0x7F { s.push(c as u8 as char); } else { s.push('?'); } }
                s
            } else { alloc::string::String::new() }
        } else { alloc::string::String::new() }
    };
    vck_driver::driver_println!("add_device: pdo={:p} name={}", pdo, pdo_name);

    // Attach an UNBOUND filter to the physical device object before any FSD mounts.
    // The filter has volume=NULL → all IRPs pass through transparently.
    // IOCTL_JVCK_PREPARE will later find this filter by name in the PDO map.
    match vck_driver::filter::attach_filter_to_raw_device(driver, pdo) {
        Ok((filter_do, lower_do)) => {
            vck_driver::driver_println!(
                "add_device: filter attached filter={:p} lower={:p}", filter_do, lower_do
            );
            REGISTRY.add_pdo_filter(pdo, filter_do, lower_do, pdo_name);
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

/// Send a no-input/no-output IOCTL to our own control device synchronously
/// Routing through the IRP path runs the handler on the expanded kernel stack
/// (the detach/crypto path is stack-hungry) and in a consistent context.
///
/// # Safety
/// `device` must be our live control device object. Must be called at
/// PASSIVE_LEVEL (the wait below requires it).
unsafe fn send_self_ioctl(device: PDEVICE_OBJECT, code: u32) -> NTSTATUS {
    let mut event: KEVENT = core::mem::zeroed();
    let mut iosb: IO_STATUS_BLOCK = core::mem::zeroed();
    KeInitializeEvent(&mut event, NotificationEvent, 0);
    let irp = IoBuildDeviceIoControlRequest(
        code,
        device,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        0,
        0, // InternalDeviceIoControl = FALSE → IRP_MJ_DEVICE_CONTROL
        &mut event,
        &mut iosb,
    );
    if irp.is_null() {
        return STATUS_UNSUCCESSFUL;
    }
    let mut status = IofCallDriver(device, irp);
    if status == STATUS_PENDING {
        let _ = KeWaitForSingleObject(
            (&mut event as *mut KEVENT).cast::<c_void>(),
            Executive,
            _MODE::KernelMode as i8,
            0,
            core::ptr::null_mut(),
        );
        status = iosb.__bindgen_anon_1.Status;
    }
    status
}

/// Detach all data volumes by self-sending `IOCTL_VCK_DETACH_ALL_VOLUMES`.
/// Shared by `driver_unload` and the `IRP_MJ_SHUTDOWN` path. OS (handover)
/// volumes are left bound (the IOCTL handler skips them).
///
/// # Safety
/// Must be called at PASSIVE_LEVEL with the control device still present.
unsafe fn driver_shutdown() {
    let device = CONTROL_DEVICE.lock().as_ref().map(|cd| cd.device_object());
    if let Some(device) = device {
        let st = send_self_ioctl(device, IOCTL_VCK_DETACH_ALL_VOLUMES);
        vck_driver::driver_println!("driver_shutdown: detach-all status=0x{:08x}", st);
    }
}

unsafe extern "C" fn driver_unload(_driver: PDRIVER_OBJECT) {
    // Detach all data volumes first (via self-IOCTL → expanded stack).
    driver_shutdown();

    // An encrypted OS (system) volume is being decrypted live by this driver.
    // Unloading would leave C: reading raw ciphertext → guaranteed corruption.
    // Refuse by bugchecking with STATUS_INVALID_DEVICE_STATE as a parameter.
    if REGISTRY.has_encrypted_os_volume() {
        vck_driver::driver_println!(
            "sample-driver: unload refused — OS volume encrypted; bugchecking"
        );
        const STATUS_INVALID_DEVICE_STATE: u64 = 0xC000_0184;
        // Custom bug check code "VCK\0" — identifiable in the crash dump. P1 is
        // STATUS_INVALID_DEVICE_STATE indicating why the unload was refused.
        const VCK_BUGCHECK: u32 = 0x5643_4B00;
        wdk_sys::ntddk::KeBugCheckEx(VCK_BUGCHECK, STATUS_INVALID_DEVICE_STATE, 0, 0, 0);
    }

    // Cleanup: tear down the control device.
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
        IRP_MJ_SHUTDOWN => {
            vck_driver::driver_println!("sample-driver: IRP_MJ_SHUTDOWN");
            // 1. Pause the OS volume sweep (stops the boundary advancing; waits
            //    for any in-flight batch). The OS volume filter stays bound so
            //    live shutdown writes remain encrypted.
            let dev = CONTROL_DEVICE.lock().as_ref().map(|cd| cd.device_object());
            if let Some(dev) = dev {
                let _ = send_self_ioctl(dev, IOCTL_VCK_PAUSE_OS_VOLUME);
            }
            // 2. Detach all data volumes.
            driver_shutdown();
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

    // Reference the requestor's primary token so the authorization policy can
    // check admin membership. Held in this frame (released on drop) and borrowed
    // by the auth context; the dispatch runs synchronously below.
    let requestor_token = unsafe { AccessToken::from_process(IoGetRequestorProcess(irp)) };
    let requestor_token_ptr = requestor_token
        .as_ref()
        .map_or(core::ptr::null(), |t| t as *const AccessToken);

    // Run the dispatch on an expanded kernel stack (the metadata/crypto path is
    // stack-hungry and calls down the storage stack). Fall back to the current
    // stack if expansion fails.
    let mut ex = ExpandCtx {
        ioctl_code,
        requestor_mode,
        requestor_token: requestor_token_ptr,
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
            requestor_token: requestor_token.as_ref(),
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
