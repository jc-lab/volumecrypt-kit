//! Filter IRP interception.
//!
//! Two transforms keep the metadata regions invisible to the OS and present the
//! data region as the whole volume:
//! - Size-query IOCTLs (`GET_LENGTH_INFO`, `GET_PARTITION_INFO[_EX]`) have their
//!   reported length rewritten to the data-region size on completion.
//! - READ/WRITE byte offsets are shifted down by `offset_sector` so OS-relative
//!   LBA 0 maps to the first data sector (a no-op for footer-only data volumes,
//!   where `offset_sector == 0`).
//!
//! AES-XTS in-flight crypto (decrypt on read completion, encrypt on write) will
//! be layered on top of these transforms.

use core::ffi::c_void;

use wdk_sys::{
    ntddk::IofCallDriver, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE, NTSTATUS,
    PDEVICE_OBJECT, PIO_STACK_LOCATION, PIRP, SL_INVOKE_ON_CANCEL, SL_INVOKE_ON_ERROR,
    SL_INVOKE_ON_SUCCESS, SL_PENDING_RETURNED,
};

use crate::{device::DeviceExtension, filter::pass_through, nt::nt_success, registry::AttachedVolume};

// Returning this from a completion routine lets the IRP keep completing up the
// stack (as opposed to STATUS_MORE_PROCESSING_REQUIRED, which halts it).
const STATUS_CONTINUE_COMPLETION: NTSTATUS = 0;

// METHOD_BUFFERED size-query IOCTLs and the byte offset of the LONGLONG length
// field within their (system-buffer) output structure.
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C; // GET_LENGTH_INFORMATION.Length @ 0
const IOCTL_DISK_GET_PARTITION_INFO: u32 = 0x0007_4004; // PARTITION_INFORMATION.PartitionLength @ 8
const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048; // PARTITION_INFORMATION_EX.PartitionLength @ 16

/// Byte offset of the 8-byte length field to rewrite, for the size-query IOCTLs
/// we intercept; `None` for any other control code.
fn size_field_offset(ioctl_code: u32) -> Option<usize> {
    match ioctl_code {
        IOCTL_DISK_GET_LENGTH_INFO => Some(0),
        IOCTL_DISK_GET_PARTITION_INFO => Some(8),
        IOCTL_DISK_GET_PARTITION_INFO_EX => Some(16),
        _ => None,
    }
}

unsafe fn current_sl(irp: PIRP) -> PIO_STACK_LOCATION {
    (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation
}

unsafe fn next_sl(irp: PIRP) -> PIO_STACK_LOCATION {
    current_sl(irp).offset(-1)
}

/// Entry point for every IRP arriving on a filter device object. Reads the
/// per-volume context from the device extension and routes by major function.
///
/// # Safety
/// `filter_do` must be one of this driver's filter device objects and `irp` a
/// valid IRP it owns.
pub unsafe fn handle_filter_irp(filter_do: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    let ext = DeviceExtension::of(filter_do);
    let lower = ext.lower_device;
    if ext.volume.is_null() {
        return pass_through(lower, irp);
    }
    let volume = &*ext.volume;

    let stack = current_sl(irp);
    let major = (*stack).MajorFunction as u32;
    match major {
        IRP_MJ_READ | IRP_MJ_WRITE => {
            shift_offset(volume, stack);
            pass_through(lower, irp)
        }
        IRP_MJ_DEVICE_CONTROL => {
            let code = (*stack).Parameters.DeviceIoControl.IoControlCode;
            if size_field_offset(code).is_some() {
                intercept_size_ioctl(volume, lower, irp)
            } else {
                pass_through(lower, irp)
            }
        }
        _ => pass_through(lower, irp),
    }
}

/// Shift a READ/WRITE byte offset down by the data-region start so OS-relative
/// LBA 0 lands on the first data sector. No-op when `offset_sector == 0`.
unsafe fn shift_offset(volume: &AttachedVolume, stack: PIO_STACK_LOCATION) {
    let shift = volume
        .offset_sector()
        .saturating_mul(volume.sector_size as u64);
    if shift == 0 {
        return;
    }
    // READ and WRITE overlay the same `ByteOffset` field in the parameter union.
    let byte_offset = &mut (*stack).Parameters.Read.ByteOffset;
    byte_offset.QuadPart += shift as i64;
}

/// Forward a size-query IOCTL down the stack with a completion routine that
/// rewrites the reported length to the data-region size.
unsafe fn intercept_size_ioctl(
    volume: &AttachedVolume,
    lower: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    // Copy our stack location to the next so the lower driver sees identical
    // parameters, then install our completion routine on it.
    let cur = current_sl(irp);
    let next = next_sl(irp);
    core::ptr::copy_nonoverlapping(cur, next, 1);
    (*next).CompletionRoutine = Some(size_ioctl_completion);
    (*next).Context = (volume as *const AttachedVolume) as *mut c_void;
    (*next).Control =
        (SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL) as u8;

    IofCallDriver(lower, irp)
}

/// Rewrite the length field of a completed size-query IOCTL to the data-region
/// byte size, hiding the header/footer metadata from the OS.
unsafe extern "C" fn size_ioctl_completion(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
    context: *mut c_void,
) -> NTSTATUS {
    let volume = &*(context as *const AttachedVolume);
    let stack = current_sl(irp);
    let code = (*stack).Parameters.DeviceIoControl.IoControlCode;
    let status = (*irp).IoStatus.__bindgen_anon_1.Status;

    if nt_success(status) {
        if let Some(field_off) = size_field_offset(code) {
            let info = (*irp).IoStatus.Information as usize;
            let sysbuf = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
            if !sysbuf.is_null() && info >= field_off + 8 {
                let data_bytes = volume
                    .data_sectors()
                    .saturating_mul(volume.sector_size as u64);
                core::ptr::copy_nonoverlapping(
                    data_bytes.to_le_bytes().as_ptr(),
                    sysbuf.add(field_off),
                    8,
                );
                crate::driver_println!(
                    "filter: size ioctl 0x{:08x} reported as {} bytes",
                    code,
                    data_bytes
                );
            }
        }
    }

    // Propagate a pending result up the stack (IoMarkIrpPending equivalent).
    if (*irp).PendingReturned != 0 {
        (*stack).Control |= SL_PENDING_RETURNED as u8;
    }
    STATUS_CONTINUE_COMPLETION
}
