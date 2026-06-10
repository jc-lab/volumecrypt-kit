//! Filter IRP interception.
//!
//! Three transforms are applied to live filesystem I/O:
//!
//! 1. **Size-query IOCTLs** (`GET_LENGTH_INFO`, `GET_PARTITION_INFO[_EX]`):
//!    completion rewrites the reported length to the data-region size, hiding
//!    the header/footer metadata from the OS.
//!
//! 2. **READ/WRITE byte-offset shift**: `offset_sector` is added to the byte
//!    offset so OS-relative LBA 0 lands on the first data sector.
//!
//! 3. **AES-XTS in-flight crypto** via two dedicated PASSIVE_LEVEL threads:
//!    - READ:  io_queue thread does synchronous lower read; worker_queue thread decrypts.
//!    - WRITE: worker_queue thread encrypts into a shadow buffer; io_queue thread writes.
//!    See `irp_queue.rs` for the full queue/thread implementation.

use core::ffi::c_void;

use wdk_sys::{
    ntddk::{ExFreePool, IofCallDriver, IofCompleteRequest},
    CCHAR, IO_NO_INCREMENT, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE, NTSTATUS,
    PDEVICE_OBJECT, PIO_STACK_LOCATION, PIRP,
    SL_INVOKE_ON_CANCEL, SL_INVOKE_ON_ERROR, SL_INVOKE_ON_SUCCESS, SL_PENDING_RETURNED,
};

use core::sync::atomic::Ordering;

use crate::{
    device::DeviceExtension,
    filter::{irp_queue, pass_through},
    nt::nt_success,
    registry::AttachedVolume,
};

const STATUS_CONTINUE_COMPLETION: NTSTATUS = 0;
const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022u32 as i32;

const IOCTL_DISK_GET_LENGTH_INFO: u32     = 0x0007_405C;
const IOCTL_DISK_GET_PARTITION_INFO: u32   = 0x0007_4004;
const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048;

fn size_field_offset(code: u32) -> Option<usize> {
    match code {
        IOCTL_DISK_GET_LENGTH_INFO      => Some(0),
        IOCTL_DISK_GET_PARTITION_INFO   => Some(8),
        IOCTL_DISK_GET_PARTITION_INFO_EX => Some(16),
        _ => None,
    }
}

unsafe fn current_sl(irp: PIRP) -> PIO_STACK_LOCATION {
    (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation
}

unsafe fn next_sl(irp: PIRP) -> PIO_STACK_LOCATION {
    current_sl(irp).offset(-1)
}

// ---------------------------------------------------------------------------
// Size-query IOCTL interception (runs entirely at completion IRQL — no crypto)
// ---------------------------------------------------------------------------

/// Context stored in next-stack-location for size IOCTL completion.
#[repr(C)]
struct SizeCtx {
    data_bytes: u64,
}

unsafe fn intercept_size_ioctl(
    volume: &AttachedVolume,
    lower: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    // POOL_FLAG_NON_PAGED = 0x40
    let ctx = wdk_sys::ntddk::ExAllocatePool2(
        0x0000_0000_0000_0040,
        core::mem::size_of::<SizeCtx>() as u64,
        u32::from_le_bytes(*b"VCKI"),
    ) as *mut SizeCtx;
    if ctx.is_null() {
        return pass_through(lower, irp);
    }
    (*ctx).data_bytes = volume.data_sectors().saturating_mul(volume.sector_size as u64);

    let cur  = current_sl(irp);
    let next = next_sl(irp);
    core::ptr::copy_nonoverlapping(cur, next, 1);
    (*next).CompletionRoutine = Some(size_ioctl_completion);
    (*next).Context = ctx.cast::<c_void>();
    (*next).Control = (SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL) as u8;
    IofCallDriver(lower, irp)
}

unsafe extern "C" fn size_ioctl_completion(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
    context: *mut c_void,
) -> NTSTATUS {
    let ctx = &*(context as *const SizeCtx);
    let stack = current_sl(irp);
    let code  = (*stack).Parameters.DeviceIoControl.IoControlCode;
    let status = (*irp).IoStatus.__bindgen_anon_1.Status;

    if nt_success(status) {
        if let Some(field_off) = size_field_offset(code) {
            let info = (*irp).IoStatus.Information as usize;
            let sysbuf = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
            if !sysbuf.is_null() && info >= field_off + 8 {
                core::ptr::copy_nonoverlapping(
                    ctx.data_bytes.to_le_bytes().as_ptr(),
                    sysbuf.add(field_off),
                    8,
                );
                crate::driver_println!(
                    "filter: size ioctl 0x{:08x} reported as {} bytes",
                    code, ctx.data_bytes
                );
            }
        }
    }

    ExFreePool(context);

    if (*irp).PendingReturned != 0 {
        (*current_sl(irp)).Control |= SL_PENDING_RETURNED as u8;
    }
    STATUS_CONTINUE_COMPLETION
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

unsafe fn block_irp(irp: PIRP, status: NTSTATUS) {
    (*irp).IoStatus.__bindgen_anon_1.Status = status;
    (*irp).IoStatus.Information = 0;
    IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
}

fn is_metadata_sector(volume: &AttachedVolume, byte_offset: u64, sector_size: u64) -> bool {
    if sector_size == 0 { return false; }
    let lba = byte_offset / sector_size;
    data_relative(volume, lba).is_none()
}

fn data_relative(volume: &AttachedVolume, abs_lba: u64) -> Option<u64> {
    let offset = volume.offset_sector();
    let total  = volume.data_sectors();
    abs_lba.checked_sub(offset).filter(|rel| *rel < total)
}

unsafe fn shift_offset(volume: &AttachedVolume, stack: PIO_STACK_LOCATION) {
    let shift = volume.offset_sector().saturating_mul(volume.sector_size as u64);
    if shift == 0 { return; }
    let byte_offset = &mut (*stack).Parameters.Read.ByteOffset;
    byte_offset.QuadPart += shift as i64;
}

// ---------------------------------------------------------------------------
// Main dispatch entry point
// ---------------------------------------------------------------------------

/// Entry point for every IRP arriving on a filter device object.
///
/// # Safety
/// `filter_do` must be one of this driver's filter device objects and `irp`
/// a valid IRP it currently owns.
pub unsafe fn handle_filter_irp(filter_do: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    let ext   = DeviceExtension::of(filter_do);
    let lower = ext.lower_device;

    if ext.volume.is_null() {
        return pass_through(lower, irp);
    }
    let volume = &*ext.volume;

    let stack = current_sl(irp);
    let major = (*stack).MajorFunction as u32;

    match major {
        IRP_MJ_READ => {
            shift_offset(volume, stack);
            let byte_off = (*stack).Parameters.Read.ByteOffset.QuadPart as u64;
            if is_metadata_sector(volume, byte_off, volume.sector_size as u64)
                && (*irp).RequestorMode != 0
            {
                block_irp(irp, STATUS_ACCESS_DENIED);
                return STATUS_ACCESS_DENIED;
            }
            irp_queue::enqueue_read(irp, volume as *const _, lower)
        }

        IRP_MJ_WRITE => {
            shift_offset(volume, stack);
            let byte_off = (*stack).Parameters.Write.ByteOffset.QuadPart as u64;
            if is_metadata_sector(volume, byte_off, volume.sector_size as u64)
                && (*irp).RequestorMode != 0
            {
                block_irp(irp, STATUS_ACCESS_DENIED);
                return STATUS_ACCESS_DENIED;
            }
            irp_queue::enqueue_write(irp, volume as *const _, lower)
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
