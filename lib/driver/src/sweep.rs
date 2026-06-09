//! Background encrypt/decrypt sweep worker.
//!
//! A single system thread polls the registry and drives
//! [`AttachedVolume::sweep_step`](crate::registry::AttachedVolume::sweep_step)
//! for every volume currently in an Encrypting/Decrypting state, persisting
//! progress as it goes. Created at `DriverEntry` and stopped at `DriverUnload`.

use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::null_mut;

use vck_common::{VckError, VckResult};
use wdk_sys::{
    ntddk::{
        KeInitializeEvent, KeSetEvent, KeWaitForSingleObject, ObReferenceObjectByHandle,
        ObfDereferenceObject, PsCreateSystemThread, PsTerminateSystemThread, ZwClose,
    },
    HANDLE, KEVENT, LARGE_INTEGER, _EVENT_TYPE::NotificationEvent, _KWAIT_REASON::Executive,
    _MODE::KernelMode,
};

use crate::nt::{nt_success, STATUS_SUCCESS};
use crate::registry::VolumeAttachRegistry;

/// Sectors processed per volume per loop iteration (64 KiB at 512-byte sectors
/// to keep allocations small on a tight kernel stack).
const BATCH_SECTORS: u64 = 128;
/// Expanded stack size for each sweep batch (crypto + storage stack call-chain
/// consumes most of the default 12 KiB system-thread stack).
const SWEEP_STACK_SIZE: usize = 0x8000; // 32 KiB
const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
const SYNCHRONIZE: u32 = 0x0010_0000;
// Relative wait timeouts (negative = relative, units of 100 ns).
const TICK_ACTIVE_100NS: i64 = -100_000; // 10 ms between batches while working
const TICK_IDLE_100NS: i64 = -2_000_000; // 200 ms poll while idle

struct SweepContext {
    registry: &'static VolumeAttachRegistry,
    stop_event: KEVENT,
}

pub struct SweepWorker {
    // Boxed so the address stays stable while the thread holds a raw pointer.
    ctx: Box<SweepContext>,
    // Referenced PETHREAD object (null if the thread could not be referenced).
    thread: *mut c_void,
}

// The raw pointers are only touched under the documented start/stop protocol.
unsafe impl Send for SweepWorker {}
unsafe impl Sync for SweepWorker {}

impl SweepWorker {
    /// Create and start the sweep thread.
    pub fn start(registry: &'static VolumeAttachRegistry) -> VckResult<Self> {
        let mut ctx = Box::new(SweepContext {
            registry,
            stop_event: unsafe { core::mem::zeroed() },
        });
        unsafe {
            KeInitializeEvent(&mut ctx.stop_event, NotificationEvent, 0);
        }

        let ctx_ptr: *mut SweepContext = &mut *ctx;
        let mut handle: HANDLE = null_mut();
        let status = unsafe {
            PsCreateSystemThread(
                &mut handle,
                THREAD_ALL_ACCESS,
                null_mut(),
                null_mut(),
                null_mut(),
                Some(sweep_thread),
                ctx_ptr.cast::<c_void>(),
            )
        };
        if !nt_success(status) {
            return Err(VckError::Io("PsCreateSystemThread failed".into()));
        }

        // Keep a reference to the thread object so we can wait on it at
        // shutdown, then drop the handle.
        let mut thread_obj: *mut c_void = null_mut();
        let ref_status = unsafe {
            ObReferenceObjectByHandle(
                handle,
                SYNCHRONIZE,
                null_mut(),
                KernelMode as i8,
                &mut thread_obj,
                null_mut(),
            )
        };
        unsafe {
            let _ = ZwClose(handle);
        }
        if !nt_success(ref_status) {
            // Thread is running but unjoinable: signal it to exit and fail.
            unsafe {
                let _ = KeSetEvent(&mut ctx.stop_event, 0, 0);
            }
            return Err(VckError::Io("ObReferenceObjectByHandle(thread) failed".into()));
        }

        Ok(Self {
            ctx,
            thread: thread_obj,
        })
    }

    /// Signal the worker to stop and wait for it to terminate.
    pub fn stop(self) {
        unsafe {
            let _ = KeSetEvent(
                &self.ctx.stop_event as *const KEVENT as *mut KEVENT,
                0,
                0,
            );
            if !self.thread.is_null() {
                let _ = KeWaitForSingleObject(
                    self.thread,
                    Executive,
                    KernelMode as i8,
                    0,
                    null_mut(),
                );
                ObfDereferenceObject(self.thread);
            }
        }
        // `ctx` (and its KEVENT) is dropped here, after the thread has exited.
    }
}

unsafe extern "C" fn sweep_thread(context: *mut c_void) {
    let ctx = &*(context as *const SweepContext);
    loop {
        let mut active = false;
        for volume in ctx.registry.all() {
            match volume.sweep_step(BATCH_SECTORS) {
                Ok(true) => active = true,
                Ok(false) => {}
                Err(err) => {
                    crate::driver_println!("sweep: step error: {}", err);
                }
            }
        }

        let timeout = if active {
            TICK_ACTIVE_100NS
        } else {
            TICK_IDLE_100NS
        };
        if wait_stop(&ctx.stop_event, timeout) {
            break;
        }
    }
    let _ = PsTerminateSystemThread(STATUS_SUCCESS);
}

/// Wait on the stop event for `timeout_100ns` (negative = relative). Returns
/// `true` when the event is signaled (stop requested).
unsafe fn wait_stop(event: &KEVENT, timeout_100ns: i64) -> bool {
    let mut timeout = LARGE_INTEGER {
        QuadPart: timeout_100ns,
    };
    let status = KeWaitForSingleObject(
        event as *const KEVENT as *mut c_void,
        Executive,
        KernelMode as i8,
        0,
        &mut timeout,
    );
    status == STATUS_SUCCESS
}
