//! Filter IRP interception.
//!
//! Three transforms are applied to live filesystem I/O:
//!
//! 1. **Size-query IOCTLs** (`GET_LENGTH_INFO`, `GET_PARTITION_INFO[_EX]`):
//!    completion rewrites the reported length to the data-region size, hiding
//!    the header/footer metadata from the OS.
//!
//! 2. **READ/WRITE byte-offset shift**: `offset_sector` is added to the byte
//!    offset so OS-relative LBA 0 lands on the first data sector. No-op when
//!    `offset_sector == 0` (footer-only data volumes).
//!
//! 3. **AES-XTS in-flight crypto**:
//!    - READ: a completion routine decrypts sectors that lie within the
//!      encrypted span in-place (the MDL pages are writable in kernel mode).
//!    - WRITE: a shadow (NonPagedPool) buffer is allocated, the caller's data is
//!      copied and encrypted, and the IRP's MDL is replaced with one covering the
//!      shadow buffer. A completion routine restores the original MDL and frees
//!      the shadow resources.
//!
//! `encrypted_offset` is fetched lock-free from the `EncryptionEngine` snapshot
//! so the filter hot-path does not block on the progress mutex.

use core::ffi::c_void;
use core::ptr::null_mut;

use wdk_sys::{
    ntddk::{
        ExAllocatePool2, ExFreePool, IofCompleteRequest, IoAllocateMdl, IoFreeMdl, IofCallDriver,
        MmBuildMdlForNonPagedPool, MmMapLockedPagesSpecifyCache,
    },
    CCHAR, IO_NO_INCREMENT, IRP_MJ_DEVICE_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE, NTSTATUS,
    PDEVICE_OBJECT, PIO_STACK_LOCATION, PIRP, PMDL, SL_INVOKE_ON_CANCEL, SL_INVOKE_ON_ERROR,
    SL_INVOKE_ON_SUCCESS, SL_PENDING_RETURNED,
};

use core::sync::atomic::Ordering;

use crate::{
    crypto::pipeline::CryptoPipeline,
    device::DeviceExtension,
    filter::pass_through,
    nt::nt_success,
    registry::AttachedVolume,
};

// POOL_FLAG_NON_PAGED = 0x40 (POOL_FLAG_NON_PAGED from ntddk).
const POOL_FLAG_NON_PAGED: u64 = 0x0000_0000_0000_0040;
// Allocation tag "VCKI" (little-endian).
const VCK_POOL_TAG: u32 = u32::from_le_bytes(*b"VCKI");

const STATUS_CONTINUE_COMPLETION: NTSTATUS = 0;
const STATUS_MORE_PROCESSING_REQUIRED: NTSTATUS = 0x0000_0103u32 as i32;
const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022u32 as i32;

// METHOD_BUFFERED size-query IOCTLs: byte offset of the 8-byte length field
// within the (system-buffer) output structure.
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C; // GET_LENGTH_INFORMATION.Length @ 0
const IOCTL_DISK_GET_PARTITION_INFO: u32 = 0x0007_4004; // PARTITION_INFORMATION.PartitionLength @ 8
const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048; // PARTITION_INFORMATION_EX.PartitionLength @ 16

fn size_field_offset(code: u32) -> Option<usize> {
    match code {
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

/// Map the locked MDL pages into system address space (equivalent of
/// `MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority)`).
unsafe fn mdl_system_address(mdl: PMDL) -> *mut u8 {
    // MmMappedSystemVa / MmMapLockedPagesSpecifyCache with NormalPagePriority=16.
    // MappedSystemVa may already be set for MDLs from the I/O manager; check it
    // first to avoid mapping twice.
    if !(*mdl).MappedSystemVa.is_null() {
        return (*mdl).MappedSystemVa.cast::<u8>();
    }
    MmMapLockedPagesSpecifyCache(
        mdl,
        0, // KernelMode
        1, // MmCached
        null_mut(),
        0, // BugCheckOnFailure = FALSE
        16, // NormalPagePriority
    )
    .cast::<u8>()
}

// --- Per-IRP context for the WRITE shadow buffer --------------------------------

/// Stored via `Context` in the write completion stack location.
#[repr(C)]
struct WriteCtx {
    /// The original MDL we replaced (restored on completion).
    original_mdl: PMDL,
    /// NonPagedPool buffer whose pages back the shadow MDL.
    shadow_buf: *mut u8,
    /// MDL we built over the shadow buffer.
    shadow_mdl: PMDL,
}

// --- READ: completion decrypts in-place ----------------------------------------

unsafe fn intercept_read(volume: &AttachedVolume, lower: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    let cur = current_sl(irp);
    let next = next_sl(irp);
    core::ptr::copy_nonoverlapping(cur, next, 1);
    (*next).CompletionRoutine = Some(read_completion);
    (*next).Context = (volume as *const AttachedVolume) as *mut c_void;
    (*next).Control = (SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL) as u8;
    IofCallDriver(lower, irp)
}

unsafe extern "C" fn read_completion(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
    context: *mut c_void,
) -> NTSTATUS {
    let volume = &*(context as *const AttachedVolume);
    let status = (*irp).IoStatus.__bindgen_anon_1.Status;
    if nt_success(status) {
        let stack = current_sl(irp);
        let byte_offset = (*stack).Parameters.Read.ByteOffset.QuadPart as u64;
        let length = (*stack).Parameters.Read.Length as usize;

        if let Some(pipeline) = pipeline_for(volume) {
            let sector_size = volume.sector_size as usize;
            if sector_size > 0 && length > 0 {
                // first_abs_lba in the raw device space (already shifted by filter).
                let first_abs_lba = byte_offset / sector_size as u64;
                if let Some(first_rel) = data_relative(volume, first_abs_lba) {
                    let mdl = (*irp).MdlAddress;
                    if !mdl.is_null() {
                        let ptr = mdl_system_address(mdl);
                        if !ptr.is_null() {
                            let buf = core::slice::from_raw_parts_mut(
                                ptr,
                                length.min(sector_size * (length / sector_size)),
                            );
                            // Read boundary WITHOUT holding the encryption lock —
                            // the lock is held by the sweep during its I/O, so
                            // acquiring it here would deadlock.
                            let encrypted_boundary =
                                volume.encrypted_boundary.load(Ordering::Acquire);
                            crate::driver_println!(
                                "filter: read lba={} rel={} sectors={} boundary={}",
                                first_abs_lba,
                                first_rel,
                                buf.len() / sector_size,
                                encrypted_boundary
                            );
                            pipeline.decrypt_read(
                                first_rel,
                                encrypted_boundary,
                                buf,
                                sector_size,
                            );
                        }
                    }
                }
            }
        }
    }

    if (*irp).PendingReturned != 0 {
        let stack = current_sl(irp);
        (*stack).Control |= SL_PENDING_RETURNED as u8;
    }
    STATUS_CONTINUE_COMPLETION
}

// --- WRITE: shadow-buffer encrypts caller data before sending down -------------

unsafe fn intercept_write(volume: &AttachedVolume, lower: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    let stack = current_sl(irp);
    let byte_offset = (*stack).Parameters.Write.ByteOffset.QuadPart as u64;
    let length = (*stack).Parameters.Write.Length as usize;
    let sector_size = volume.sector_size as usize;

    // Determine the relative sector range; fall through to pass-through if
    // the write is outside the data region or there's nothing to encrypt.
    let needs_crypto = if sector_size > 0 && length > 0 {
        let first_abs_lba = byte_offset / sector_size as u64;
        match data_relative(volume, first_abs_lba) {
            Some(first_rel) => {
                // Lock-free read — see encrypted_boundary comment on AttachedVolume.
                let encrypted_boundary = volume.encrypted_boundary.load(Ordering::Acquire);
                encrypted_boundary > 0 && first_rel < encrypted_boundary
            }
            None => false,
        }
    } else {
        false
    };

    if !needs_crypto {
        return pass_through(lower, irp);
    }

    // Allocate a NonPagedPool shadow buffer for the (encrypted) outgoing data.
    let shadow_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, length as u64, VCK_POOL_TAG) as *mut u8;
    if shadow_buf.is_null() {
        return pass_through(lower, irp);
    }

    // Copy caller data from the original MDL.
    let orig_mdl = (*irp).MdlAddress;
    if orig_mdl.is_null() {
        ExFreePool(shadow_buf.cast::<c_void>());
        return pass_through(lower, irp);
    }
    let src = mdl_system_address(orig_mdl);
    if src.is_null() {
        ExFreePool(shadow_buf.cast::<c_void>());
        return pass_through(lower, irp);
    }
    core::ptr::copy_nonoverlapping(src, shadow_buf, length);

    // Encrypt the copy.
    if let Some(pipeline) = pipeline_for(volume) {
        let first_abs_lba = byte_offset / sector_size as u64;
        if let Some(first_rel) = data_relative(volume, first_abs_lba) {
            let encrypted_boundary = volume.encrypted_boundary.load(Ordering::Acquire);
            let buf = core::slice::from_raw_parts_mut(shadow_buf, length);
            pipeline.encrypt_write(first_rel, encrypted_boundary, buf, sector_size);
        }
    }

    // Build an MDL over the shadow buffer.
    let shadow_mdl = IoAllocateMdl(
        shadow_buf.cast::<c_void>(),
        length as u32,
        0, // SecondaryBuffer = FALSE
        0, // ChargeQuota = FALSE
        null_mut(),
    );
    if shadow_mdl.is_null() {
        ExFreePool(shadow_buf.cast::<c_void>());
        return pass_through(lower, irp);
    }
    MmBuildMdlForNonPagedPool(shadow_mdl);

    // Install the context and completion routine.
    let ctx = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        core::mem::size_of::<WriteCtx>() as u64,
        VCK_POOL_TAG,
    ) as *mut WriteCtx;
    if ctx.is_null() {
        IoFreeMdl(shadow_mdl);
        ExFreePool(shadow_buf.cast::<c_void>());
        return pass_through(lower, irp);
    }
    (*ctx).original_mdl = orig_mdl;
    (*ctx).shadow_buf = shadow_buf;
    (*ctx).shadow_mdl = shadow_mdl;

    // Swap the IRP's MDL.
    (*irp).MdlAddress = shadow_mdl;

    let cur = current_sl(irp);
    let next = next_sl(irp);
    core::ptr::copy_nonoverlapping(cur, next, 1);
    (*next).CompletionRoutine = Some(write_completion);
    (*next).Context = ctx.cast::<c_void>();
    (*next).Control = (SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL) as u8;

    IofCallDriver(lower, irp)
}

unsafe extern "C" fn write_completion(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
    context: *mut c_void,
) -> NTSTATUS {
    let ctx = &mut *(context as *mut WriteCtx);

    // Restore the original MDL so the I/O manager sees the unmodified IRP.
    (*irp).MdlAddress = ctx.original_mdl;

    // Free shadow resources.
    IoFreeMdl(ctx.shadow_mdl);
    ExFreePool(ctx.shadow_buf.cast::<c_void>());
    ExFreePool(ctx as *mut WriteCtx as *mut c_void);

    if (*irp).PendingReturned != 0 {
        let stack = current_sl(irp);
        (*stack).Control |= SL_PENDING_RETURNED as u8;
    }
    STATUS_CONTINUE_COMPLETION
}

// --- Size-query IOCTL interception ---------------------------------------------

unsafe fn intercept_size_ioctl(
    volume: &AttachedVolume,
    lower: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    let cur = current_sl(irp);
    let next = next_sl(irp);
    core::ptr::copy_nonoverlapping(cur, next, 1);
    (*next).CompletionRoutine = Some(size_ioctl_completion);
    (*next).Context = (volume as *const AttachedVolume) as *mut c_void;
    (*next).Control = (SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL) as u8;
    IofCallDriver(lower, irp)
}

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
    if (*irp).PendingReturned != 0 {
        let stack = current_sl(irp);
        (*stack).Control |= SL_PENDING_RETURNED as u8;
    }
    STATUS_CONTINUE_COMPLETION
}

// --- Helpers -------------------------------------------------------------------

/// Complete an IRP immediately with the given status (no further processing).
unsafe fn block_irp(irp: PIRP, status: NTSTATUS) {
    (*irp).IoStatus.__bindgen_anon_1.Status = status;
    (*irp).IoStatus.Information = 0;
    IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
}

/// Return true when `byte_offset` addresses a metadata sector (outside the
/// data region). The filter must block UserMode access to these sectors and
/// allow KernelMode (driver-internal) I/O to pass through.
fn is_metadata_sector(volume: &AttachedVolume, byte_offset: u64, sector_size: u64) -> bool {
    if sector_size == 0 { return false; }
    let lba = byte_offset / sector_size;
    // data_relative returns None for anything outside [offset_sector, offset_sector+data_sectors).
    data_relative(volume, lba).is_none()
}

/// Borrow the `CryptoPipeline` for this volume, if one is present.
fn pipeline_for(volume: &AttachedVolume) -> Option<CryptoPipeline<'_>> {
    let cipher = volume.cipher.as_ref()?;
    Some(CryptoPipeline::new(cipher))
}

/// Convert an absolute LBA (already shifted by the volume's `offset_sector`)
/// into a data-region-relative sector, or `None` for metadata-region accesses.
///
/// Does NOT hold the encryption lock — uses only the immutable layout fields
/// (`offset_sector`, `data_sectors`) that are set at attach time and never change.
fn data_relative(volume: &AttachedVolume, abs_lba: u64) -> Option<u64> {
    let offset = volume.offset_sector();
    let total = volume.data_sectors();
    abs_lba.checked_sub(offset).filter(|rel| *rel < total)
}

// --- Main dispatch entry point -------------------------------------------------

/// Entry point for every IRP arriving on a filter device object.
///
/// # Safety
/// `filter_do` must be one of this driver's filter device objects and `irp` a
/// valid IRP it currently owns.
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
        IRP_MJ_READ => {
            shift_offset(volume, stack);
            // Block UserMode access to the metadata region; allow KernelMode
            // (driver-internal metadata I/O: offset_store, ATTACH reads, etc.).
            if is_metadata_sector(volume, (*stack).Parameters.Read.ByteOffset.QuadPart as u64,
                                   volume.sector_size as u64)
                && (*irp).RequestorMode != 0 // not KernelMode
            {
                block_irp(irp, STATUS_ACCESS_DENIED);
                return STATUS_ACCESS_DENIED;
            }
            intercept_read(volume, lower, irp)
        }
        IRP_MJ_WRITE => {
            shift_offset(volume, stack);
            // Block UserMode writes to the metadata region.
            if is_metadata_sector(volume, (*stack).Parameters.Write.ByteOffset.QuadPart as u64,
                                   volume.sector_size as u64)
                && (*irp).RequestorMode != 0
            {
                block_irp(irp, STATUS_ACCESS_DENIED);
                return STATUS_ACCESS_DENIED;
            }
            intercept_write(volume, lower, irp)
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

/// Shift a READ/WRITE byte offset by the data-region start so OS-relative LBA 0
/// maps to the first data sector. No-op when `offset_sector == 0`.
unsafe fn shift_offset(volume: &AttachedVolume, stack: PIO_STACK_LOCATION) {
    let shift = volume
        .offset_sector()
        .saturating_mul(volume.sector_size as u64);
    if shift == 0 {
        return;
    }
    let byte_offset = &mut (*stack).Parameters.Read.ByteOffset;
    byte_offset.QuadPart += shift as i64;
}
