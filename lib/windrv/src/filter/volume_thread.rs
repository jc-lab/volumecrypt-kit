//! Per-volume IO + sweep thread.
//!
//! Each cipher-bound filter device owns one `VolumeThread`. A single PASSIVE_LEVEL
//! system thread serializes ALL of that volume's work:
//!
//! - user READ/WRITE IRPs (enqueued from `handle_filter_irp`), and
//! - the background encrypt/decrypt sweep (one batch at a time).
//!
//! Because both run on the same thread, they can never execute concurrently:
//! the sweep's read-modify-write + boundary advance is atomic with respect to
//! every user IRP, eliminating the sweep↔IRP data races by construction.
//!
//! Lifecycle: created at bind (when a cipher-ready volume is bound to the filter),
//! the `current` volume is swapped on rebind, and the thread is stopped + freed at
//! detach (before the filter device is torn down).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

use spin::Mutex;
use vck_common::SectorIo;
use wdk_sys::{
    ntddk::{
        ExAllocatePool2, ExFreePool, IoAcquireCancelSpinLock, IoReleaseCancelSpinLock,
        IofCompleteRequest, KeInitializeEvent, KeSetEvent, KeWaitForSingleObject,
        ObReferenceObjectByHandle, ObfDereferenceObject, PsCreateSystemThread, ZwClose,
    },
    CCHAR, HANDLE, IO_NO_INCREMENT, KEVENT, LARGE_INTEGER, NTSTATUS,
    PDEVICE_OBJECT, PIO_STACK_LOCATION, PIRP,
    SL_PENDING_RETURNED,
    _EVENT_TYPE::SynchronizationEvent,
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
};

use crate::{
    crypto::pipeline::CryptoPipeline,
    device::DeviceExtension,
    nt::nt_success,
    ntddk_ex::{IoSetCancelRoutine, MmGetSystemAddressForMdlSafe},
    registry::AttachedVolume,
};

const POOL_FLAG_NON_PAGED: u64 = 0x0000_0000_0000_0040;
const VCK_POOL_TAG: u32 = u32::from_le_bytes(*b"VCKI");
const STATUS_PENDING: NTSTATUS = 0x0000_0103u32 as i32;
const STATUS_SUCCESS: NTSTATUS = 0;
const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC000_0001u32 as i32;
const STATUS_CANCELLED: NTSTATUS = 0xC000_0120u32 as i32;
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const SYNCHRONIZE: u32 = 0x0010_0000;

/// Sectors processed per sweep batch (1 MiB at 512-byte sectors).
const BATCH_SECTORS: u64 = 2048;
/// Maximum user IRPs serviced before yielding one sweep batch (bounds the time
/// the sweep waits behind a burst of user I/O).
const MAX_IRP_BURST: u32 = 64;
/// Idle wait timeout (safety net so the thread re-polls sweep state even if a
/// wake signal is missed). -5_000_000 * 100 ns = 500 ms (negative = relative).
const IDLE_TIMEOUT_100NS: i64 = -5_000_000;

// ---------------------------------------------------------------------------
// IRP queue entry
// ---------------------------------------------------------------------------

struct IrpEntry {
    irp:      PIRP,
    is_write: bool,
}

// ---------------------------------------------------------------------------
// VolumeThread
// ---------------------------------------------------------------------------

pub struct VolumeThread {
    queue:    Mutex<VecDeque<IrpEntry>>,
    /// The volume currently bound to the owning filter (swapped on rebind).
    current:  Mutex<Arc<AttachedVolume>>,
    wake:     KEVENT,
    shutdown: AtomicBool,
    thread:   *mut c_void, // PETHREAD (set after PsCreateSystemThread)
}

unsafe impl Send for VolumeThread {}
unsafe impl Sync for VolumeThread {}

impl VolumeThread {
    /// Create and start the thread for `volume`. Returns a heap box whose raw
    /// pointer is stored in the filter's DeviceExtension.
    pub unsafe fn start(volume: Arc<AttachedVolume>) -> Box<VolumeThread> {
        let mut vt = Box::new(VolumeThread {
            queue:    Mutex::new(VecDeque::new()),
            current:  Mutex::new(volume),
            wake:     core::mem::zeroed(),
            shutdown: AtomicBool::new(false),
            thread:   null_mut(),
        });
        KeInitializeEvent(&mut vt.wake, SynchronizationEvent, 0);

        let self_ptr: *mut VolumeThread = &mut *vt;
        let mut handle: HANDLE = null_mut();
        let st = PsCreateSystemThread(
            &mut handle, THREAD_ALL_ACCESS, null_mut(), null_mut(), null_mut(),
            Some(thread_main), self_ptr.cast::<c_void>(),
        );
        if !nt_success(st) {
            crate::driver_println!("volume_thread: create failed 0x{:08x}", st);
            return vt; // thread null; enqueue falls back to direct completion
        }
        let mut obj: *mut c_void = null_mut();
        let _ = ObReferenceObjectByHandle(
            handle, SYNCHRONIZE, null_mut(), KernelMode as i8, &mut obj, null_mut(),
        );
        let _ = ZwClose(handle);
        vt.thread = obj;
        vt
    }

    /// Swap the bound volume (on rebind provisional → complete).
    pub fn set_current(&self, volume: Arc<AttachedVolume>) {
        *self.current.lock() = volume;
        self.signal();
    }

    fn signal(&self) {
        unsafe { KeSetEvent(&self.wake as *const KEVENT as *mut KEVENT, 0, 0) };
    }

    /// Stop the thread, wait for it to exit, and complete any queued IRPs as
    /// cancelled. Safe to call once; consumes via Box drop afterwards.
    pub unsafe fn stop(&self) {
        self.shutdown.store(true, Ordering::Release);
        self.signal();
        if !self.thread.is_null() {
            KeWaitForSingleObject(self.thread, Executive, KernelMode as i8, 0, null_mut());
            ObfDereferenceObject(self.thread);
        }
    }
}

impl Drop for VolumeThread {
    fn drop(&mut self) {
        // Any IRPs still queued (none expected after stop drains them) are
        // completed cancelled so they do not leak.
        let mut q = self.queue.lock();
        while let Some(ep) = q.pop_front() {
            unsafe { complete_irp(ep.irp, STATUS_CANCELLED, 0) };
        }
    }
}

// ---------------------------------------------------------------------------
// Bind / enqueue / wake — called from manager.rs and dispatch
// ---------------------------------------------------------------------------

/// Ensure the filter has a running VolumeThread bound to `volume`.
///
/// - If a thread already exists, just swaps its `current` volume.
/// - Else, if `volume` has a cipher, starts a new thread.
/// - Else (no cipher, no thread): no-op — IO passes through directly.
///
/// # Safety
/// `filter_do` must be a filter device object owned by this driver.
pub unsafe fn bind(filter_do: PDEVICE_OBJECT, volume: Arc<AttachedVolume>) {
    let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
    if !(*ext).vthread.is_null() {
        (*(*ext).vthread).set_current(volume);
        return;
    }
    if volume.cipher.is_some() {
        let vt = VolumeThread::start(volume);
        (*ext).vthread = Box::into_raw(vt);
    }
}

/// Enqueue a READ/WRITE IRP onto the volume thread. Returns STATUS_PENDING.
///
/// # Safety
/// `vt` must be a live VolumeThread pointer (from the filter extension).
pub unsafe fn enqueue(vt: *mut VolumeThread, irp: PIRP, is_write: bool) -> NTSTATUS {
    let vt = &*vt;

    let mut q = vt.queue.lock();
    if vt.shutdown.load(Ordering::Acquire) {
        drop(q);
        complete_irp(irp, STATUS_CANCELLED, 0);
        return STATUS_CANCELLED;
    }
    // Mark pending before returning STATUS_PENDING. Cancellation is handled at
    // dequeue (see `claim_irp`), so we install no cancel routine here.
    let sl = (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation;
    (*sl).Control |= SL_PENDING_RETURNED as u8;
    q.push_back(IrpEntry { irp, is_write });
    drop(q);
    vt.signal();
    STATUS_PENDING
}

/// Claim a dequeued IRP for processing: under the cancel spinlock, clear any
/// cancel routine and read the Cancel flag. Returns true if the IRP was
/// cancelled (and must be completed STATUS_CANCELLED instead of processed).
unsafe fn claim_cancelled(irp: PIRP) -> bool {
    let mut irql: u8 = 0;
    IoAcquireCancelSpinLock(&mut irql);
    IoSetCancelRoutine(irp, None);
    let cancelled = (*irp).Cancel != 0;
    IoReleaseCancelSpinLock(irql);
    cancelled
}

/// Wake the thread bound to `volume` (e.g. after start_encrypt transitions the
/// engine state) so the sweep resumes promptly.
pub unsafe fn wake_for(volume: &AttachedVolume) {
    let filter_do = volume.filter_device.load(Ordering::Acquire);
    if filter_do.is_null() { return; }
    let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
    if !(*ext).vthread.is_null() {
        (*(*ext).vthread).signal();
    }
}

// ---------------------------------------------------------------------------
// Thread main loop
// ---------------------------------------------------------------------------

unsafe extern "C" fn thread_main(context: *mut c_void) {
    let vt = &*(context as *const VolumeThread);
    loop {
        if vt.shutdown.load(Ordering::Acquire) {
            break;
        }
        let vol = vt.current.lock().clone();

        // (1) Service user IRPs first (bounded burst).
        let mut did = false;
        let mut n = 0u32;
        while n < MAX_IRP_BURST {
            let ep = vt.queue.lock().pop_front();
            match ep {
                Some(ep) => {
                    if claim_cancelled(ep.irp) {
                        complete_irp(ep.irp, STATUS_CANCELLED, 0);
                    } else {
                        process_irp(&vol, ep);
                    }
                    did = true;
                    n += 1;
                }
                None => break,
            }
        }

        // (2) One sweep batch (no-op unless engine is Encrypting/Decrypting).
        match vol.sweep_step(BATCH_SECTORS) {
            Ok(true)  => did = true, // more sweep work remains
            Ok(false) => {}
            Err(e)    => crate::driver_println!("volume_thread: sweep err: {}", e),
        }

        // (3) Idle → wait for a wake (new IRP / rebind / start_encrypt) or timeout.
        if !did {
            let mut timeout = LARGE_INTEGER { QuadPart: IDLE_TIMEOUT_100NS };
            KeWaitForSingleObject(
                &vt.wake as *const KEVENT as *mut c_void,
                Executive, KernelMode as i8, 0, &mut timeout,
            );
        }
    }

    // Drain remaining IRPs as cancelled.
    loop {
        let ep = vt.queue.lock().pop_front();
        match ep {
            Some(ep) => complete_irp(ep.irp, STATUS_CANCELLED, 0),
            None => break,
        }
    }
    let _ = wdk_sys::ntddk::PsTerminateSystemThread(STATUS_SUCCESS);
}

unsafe fn process_irp(vol: &AttachedVolume, ep: IrpEntry) {
    if ep.is_write {
        process_write(ep.irp, vol);
    } else {
        process_read(ep.irp, vol);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn current_sl(irp: PIRP) -> PIO_STACK_LOCATION {
    unsafe { (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation }
}

fn data_relative(volume: &AttachedVolume, abs_lba: u64) -> Option<u64> {
    let offset = volume.offset_sector();
    let total  = volume.data_sectors();
    abs_lba.checked_sub(offset).filter(|rel| *rel < total)
}

fn pipeline_for(volume: &AttachedVolume) -> Option<CryptoPipeline<'_>> {
    volume.cipher.as_ref().map(CryptoPipeline::new)
}

unsafe fn map_mdl(irp: PIRP) -> *mut u8 {
    MmGetSystemAddressForMdlSafe((*irp).MdlAddress).cast::<u8>()
}

unsafe fn complete_irp(irp: PIRP, status: NTSTATUS, information: usize) {
    (*irp).IoStatus.__bindgen_anon_1.Status = status;
    (*irp).IoStatus.Information = information as _;
    IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
}

// ---------------------------------------------------------------------------
// READ: lower read into OWN buffer → decrypt → memcpy to original → complete
// ---------------------------------------------------------------------------
//
// The lower-device I/O MUST use a buffer we own (NonPagedPool), never the
// original IRP's MDL mapping: IoBuildSynchronousFsdRequest builds a fresh MDL
// and MmProbeAndLockPages over the buffer, and locking the system-VA mapping of
// an already-locked MDL faults (PAGE_FAULT_IN_NONPAGED_AREA).

unsafe fn process_read(irp: PIRP, volume: &AttachedVolume) {
    let stack       = current_sl(irp);
    let byte_offset = (*stack).Parameters.Read.ByteOffset.QuadPart as u64;
    let length      = (*stack).Parameters.Read.Length as usize;
    let sector_size = volume.sector_size as usize;

    if sector_size == 0 || length == 0 {
        complete_irp(irp, STATUS_SUCCESS, 0);
        return;
    }
    let first_lba    = byte_offset / sector_size as u64;
    let sector_count = length / sector_size;
    if sector_count == 0 {
        complete_irp(irp, STATUS_SUCCESS, 0);
        return;
    }
    let io_len = sector_count * sector_size;

    let dst = map_mdl(irp);
    if dst.is_null() {
        complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
        return;
    }
    let frag = ExAllocatePool2(POOL_FLAG_NON_PAGED, io_len as u64, VCK_POOL_TAG) as *mut u8;
    if frag.is_null() {
        complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
        return;
    }
    let frag_slice = core::slice::from_raw_parts_mut(frag, io_len);

    let io: Arc<dyn SectorIo> = volume.sweep_io.lock().clone();
    let result = io.read_sectors(first_lba, frag_slice);

    match result {
        Err(_) => {
            ExFreePool(frag.cast());
            complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
        }
        Ok(()) => {
            if let Some(pipeline) = pipeline_for(volume) {
                if let Some(first_rel) = data_relative(volume, first_lba) {
                    let boundary = volume.encrypted_boundary.load(Ordering::Acquire);
                    pipeline.decrypt_read(first_rel, boundary, frag_slice, sector_size);
                }
            }
            core::ptr::copy_nonoverlapping(frag, dst, io_len);
            ExFreePool(frag.cast());
            complete_irp(irp, STATUS_SUCCESS, io_len);
        }
    }
}

// ---------------------------------------------------------------------------
// WRITE: copy original → OWN buffer → encrypt → lower write → complete
// ---------------------------------------------------------------------------

unsafe fn process_write(irp: PIRP, volume: &AttachedVolume) {
    let stack       = current_sl(irp);
    let byte_offset = (*stack).Parameters.Write.ByteOffset.QuadPart as u64;
    let length      = (*stack).Parameters.Write.Length as usize;
    let sector_size = volume.sector_size as usize;

    if sector_size == 0 || length == 0 {
        complete_irp(irp, STATUS_SUCCESS, 0);
        return;
    }
    let first_lba    = byte_offset / sector_size as u64;
    let sector_count = length / sector_size;
    if sector_count == 0 {
        complete_irp(irp, STATUS_SUCCESS, 0);
        return;
    }
    let io_len = sector_count * sector_size;

    let src = map_mdl(irp);
    if src.is_null() {
        complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
        return;
    }
    let frag = ExAllocatePool2(POOL_FLAG_NON_PAGED, io_len as u64, VCK_POOL_TAG) as *mut u8;
    if frag.is_null() {
        complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
        return;
    }
    core::ptr::copy_nonoverlapping(src, frag, io_len);

    let needs_crypto = match data_relative(volume, first_lba) {
        Some(first_rel) => {
            let boundary = volume.encrypted_boundary.load(Ordering::Acquire);
            boundary > 0 && first_rel < boundary
        }
        None => false,
    };
    if needs_crypto {
        if let Some(pipeline) = pipeline_for(volume) {
            if let Some(first_rel) = data_relative(volume, first_lba) {
                let boundary = volume.encrypted_boundary.load(Ordering::Acquire);
                let buf = core::slice::from_raw_parts_mut(frag, io_len);
                pipeline.encrypt_write(first_rel, boundary, buf, sector_size);
            }
        }
    }

    let io: Arc<dyn SectorIo> = volume.sweep_io.lock().clone();
    let buf = core::slice::from_raw_parts(frag as *const u8, io_len);
    let result = io.write_sectors(first_lba, buf);
    ExFreePool(frag.cast());

    match result {
        Err(_) => complete_irp(irp, STATUS_UNSUCCESSFUL, 0),
        Ok(()) => complete_irp(irp, STATUS_SUCCESS, io_len),
    }
}
