//! Single-queue IRP dispatch for transparent read/write encryption.
//!
//! One queue + one PASSIVE_LEVEL system thread processes all READ/WRITE IRPs.
//!
//! ## I/O strategy
//!
//! Uses `volume.sweep_io` (a `LowerDeviceIo` handle that bypasses the filter)
//! instead of forwarding the original IRP. This avoids the completion-chain
//! complexity of `STATUS_MORE_PROCESSING_REQUIRED` patterns and prevents races
//! with external cancel routines.
//!
//! The Arc is cloned before releasing the Mutex so the thread never holds the
//! lock during blocking I/O (prevents deadlock with the sweep worker).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use spin::Mutex;
use vck_common::SectorIo;
use wdk_sys::{
    ntddk::{
        ExAllocatePool2, ExFreePool,
        IofCompleteRequest,
        KeInitializeEvent, KeSetEvent, KeWaitForSingleObject,
        ObReferenceObjectByHandle, ObfDereferenceObject,
        PsCreateSystemThread, ZwClose,
    },
    CCHAR, HANDLE, IO_NO_INCREMENT, KEVENT, NTSTATUS,
    PDEVICE_OBJECT, PIO_STACK_LOCATION, PIRP,
    SL_PENDING_RETURNED,
    _EVENT_TYPE::SynchronizationEvent,
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
};

use crate::{
    crypto::pipeline::CryptoPipeline,
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

// ---------------------------------------------------------------------------
// IRP queue entry
// ---------------------------------------------------------------------------

pub struct IrpEntry {
    pub irp:      PIRP,
    pub volume:   *const AttachedVolume,
    pub is_write: bool,
}

unsafe impl Send for IrpEntry {}

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

struct Queue {
    entries:  Mutex<VecDeque<*mut IrpEntry>>,
    wake:     KEVENT,
    shutdown: AtomicBool,
}

unsafe impl Send for Queue {}
unsafe impl Sync for Queue {}

impl Queue {
    unsafe fn new() -> Box<Self> {
        let mut q = Box::new(Queue {
            entries:  Mutex::new(VecDeque::new()),
            wake:     core::mem::zeroed(),
            shutdown: AtomicBool::new(false),
        });
        KeInitializeEvent(&mut q.wake, SynchronizationEvent, 0);
        q
    }

    unsafe fn push(&self, ep: *mut IrpEntry) {
        self.entries.lock().push_back(ep);
        KeSetEvent(&self.wake as *const KEVENT as *mut KEVENT, 0, 0);
    }

    fn pop(&self) -> Option<*mut IrpEntry> {
        self.entries.lock().pop_front()
    }

    unsafe fn signal_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        KeSetEvent(&self.wake as *const KEVENT as *mut KEVENT, 0, 0);
    }

    unsafe fn wait(&self) {
        KeWaitForSingleObject(
            &self.wake as *const KEVENT as *mut c_void,
            Executive, KernelMode as i8, 0, null_mut(),
        );
    }
}

// ---------------------------------------------------------------------------
// FilterQueues
// ---------------------------------------------------------------------------

pub struct FilterQueues {
    queue:  Box<Queue>,
    thread: *mut c_void,
    _ctx:   Box<*const Queue>,
}

unsafe impl Send for FilterQueues {}
unsafe impl Sync for FilterQueues {}

static GLOBAL: AtomicPtr<FilterQueues> = AtomicPtr::new(null_mut());

impl FilterQueues {
    pub unsafe fn start() -> Option<Box<Self>> {
        let queue = Queue::new();
        let qptr: *const Queue = &*queue;
        let ctx = Box::new(qptr);
        let ctx_raw = &*ctx as *const *const Queue as *mut c_void;

        let mut handle: HANDLE = null_mut();
        let st = PsCreateSystemThread(
            &mut handle, THREAD_ALL_ACCESS, null_mut(), null_mut(), null_mut(),
            Some(irp_thread_fn), ctx_raw,
        );
        if !nt_success(st) {
            crate::driver_println!("irp_queue: thread create failed 0x{:08x}", st);
            return None;
        }

        let mut thread_obj: *mut c_void = null_mut();
        let _ = ObReferenceObjectByHandle(
            handle, SYNCHRONIZE, null_mut(), KernelMode as i8,
            &mut thread_obj, null_mut(),
        );
        let _ = ZwClose(handle);

        Some(Box::new(FilterQueues { queue, thread: thread_obj, _ctx: ctx }))
    }

    pub unsafe fn stop(&self) {
        self.queue.signal_shutdown();
        if !self.thread.is_null() {
            KeWaitForSingleObject(self.thread, Executive, KernelMode as i8, 0, null_mut());
            ObfDereferenceObject(self.thread);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub unsafe fn init() -> bool {
    match FilterQueues::start() {
        None => false,
        Some(q) => {
            GLOBAL.store(Box::into_raw(q), Ordering::Release);
            true
        }
    }
}

pub unsafe fn shutdown() {
    let p = GLOBAL.swap(null_mut(), Ordering::AcqRel);
    if !p.is_null() {
        let q = Box::from_raw(p);
        q.stop();
    }
}

unsafe fn enqueue(
    irp: PIRP,
    volume: *const AttachedVolume,
    is_write: bool,
    lower: PDEVICE_OBJECT,
) -> NTSTATUS {
    let p = GLOBAL.load(Ordering::Acquire);
    if p.is_null() { return crate::filter::pass_through(lower, irp); }

    // Clear any existing cancel routine so it cannot complete the IRP while
    // we hold it. Check Cancel after clearing (standard WDM pattern).
    IoSetCancelRoutine(irp, None);
    if (*irp).Cancel != 0 {
        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_CANCELLED;
        (*irp).IoStatus.Information = 0;
        IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
        return STATUS_CANCELLED;
    }

    let ep = ExAllocatePool2(
        POOL_FLAG_NON_PAGED, core::mem::size_of::<IrpEntry>() as u64, VCK_POOL_TAG,
    ) as *mut IrpEntry;
    if ep.is_null() { return crate::filter::pass_through(lower, irp); }

    (*ep).irp      = irp;
    (*ep).volume   = volume;
    (*ep).is_write = is_write;

    // Mark IRP pending before returning.
    let sl = (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation;
    (*sl).Control |= SL_PENDING_RETURNED as u8;

    (*p).queue.push(ep);
    STATUS_PENDING
}

pub unsafe fn enqueue_read(irp: PIRP, volume: *const AttachedVolume, lower: PDEVICE_OBJECT) -> NTSTATUS {
    enqueue(irp, volume, false, lower)
}

pub unsafe fn enqueue_write(irp: PIRP, volume: *const AttachedVolume, lower: PDEVICE_OBJECT) -> NTSTATUS {
    enqueue(irp, volume, true, lower)
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

/// Map the IRP's MDL to a kernel virtual address (safe at PASSIVE_LEVEL).
/// Uses MmGetSystemAddressForMdlSafe semantics: checks MdlFlags before trusting
/// MappedSystemVa (a non-null MappedSystemVa is garbage unless the flag is set).
unsafe fn map_mdl(irp: PIRP) -> *mut u8 {
    MmGetSystemAddressForMdlSafe((*irp).MdlAddress).cast::<u8>()
}

unsafe fn complete_irp(irp: PIRP, status: NTSTATUS, information: usize) {
    (*irp).IoStatus.__bindgen_anon_1.Status = status;
    (*irp).IoStatus.Information = information as _;
    IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
}

// ---------------------------------------------------------------------------
// IRP worker thread
// ---------------------------------------------------------------------------

unsafe extern "C" fn irp_thread_fn(ctx: *mut c_void) {
    let queue = &**(ctx as *const *const Queue);
    loop {
        while let Some(ep) = queue.pop() {
            process_entry(ep);
        }
        if queue.shutdown.load(Ordering::Acquire) { break; }
        queue.wait();
        if queue.shutdown.load(Ordering::Acquire) { break; }
    }
}

unsafe fn process_entry(ep: *mut IrpEntry) {
    let irp      = (*ep).irp;
    let volume   = &*(*ep).volume;
    let is_write = (*ep).is_write;
    ExFreePool(ep.cast());

    if is_write {
        process_write(irp, volume);
    } else {
        process_read(irp, volume);
    }
}

// ---------------------------------------------------------------------------
// READ: lower read into OWN buffer → decrypt → memcpy to original → complete
// ---------------------------------------------------------------------------
//
// CRITICAL: the lower-device I/O must use a buffer WE own (NonPagedPool),
// never the original IRP's MDL-mapped VA. IoBuildSynchronousFsdRequest
// builds a fresh MDL and MmProbeAndLockPages over the buffer it is given; locking
// the system-VA mapping of an already-locked MDL faults → PAGE_FAULT_IN_NONPAGED_AREA.
// So: read ciphertext into our fragment buffer, decrypt there, then memcpy into
// the original IRP's mapped buffer.

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

    // Map the original IRP buffer (memcpy target) — safe at PASSIVE_LEVEL.
    let dst = map_mdl(irp);
    if dst.is_null() {
        complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
        return;
    }

    // Allocate our own fragment buffer for the lower I/O.
    let frag = ExAllocatePool2(POOL_FLAG_NON_PAGED, io_len as u64, VCK_POOL_TAG) as *mut u8;
    if frag.is_null() {
        complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
        return;
    }
    let frag_slice = core::slice::from_raw_parts_mut(frag, io_len);

    // Clone Arc and release Mutex before blocking I/O (avoids deadlock with sweep).
    let io: Arc<dyn SectorIo> = volume.sweep_io.lock().clone();
    let result = io.read_sectors(first_lba, frag_slice);

    match result {
        Err(_) => {
            ExFreePool(frag.cast());
            complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
        }
        Ok(()) => {
            // Decrypt in our buffer, then deliver to the original IRP buffer.
            if let Some(pipeline) = pipeline_for(volume) {
                if let Some(first_rel) = data_relative(volume, first_lba) {
                    let boundary = volume.encrypted_boundary.load(Ordering::Acquire);
                    crate::driver_println!(
                        "filter: read lba={} rel={} sectors={} boundary={}",
                        first_lba, first_rel, sector_count, boundary
                    );
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
//
// Same constraint: the lower write must use our own NonPagedPool buffer, never
// the original IRP's MDL mapping. We always copy into a fragment buffer (even
// when no crypto is needed) so IoBuildSynchronousFsdRequest never locks the
// original mapping.

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

    // Always copy into our own buffer for the lower I/O.
    let frag = ExAllocatePool2(POOL_FLAG_NON_PAGED, io_len as u64, VCK_POOL_TAG) as *mut u8;
    if frag.is_null() {
        complete_irp(irp, STATUS_UNSUCCESSFUL, 0);
        return;
    }
    core::ptr::copy_nonoverlapping(src, frag, io_len);

    // Encrypt in place within our buffer if the range is inside the encrypted span.
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
