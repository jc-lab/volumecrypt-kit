// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Supplemental kernel routines not exported by wdk-sys.
//!
//! These are inline/macro functions from ntddk.h that bindgen does not emit.

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};

use wdk_sys::{
    ntddk::MmMapLockedPagesSpecifyCache, DRIVER_CANCEL, LARGE_INTEGER, PIO_STACK_LOCATION, PIRP,
    PMDL,
};

extern "C" {
    /// Query the performance counter. When `performance_frequency` is non-null
    /// the counter frequency (ticks/second) is written there. Callable at any IRQL.
    pub fn KeQueryPerformanceCounter(performance_frequency: *mut LARGE_INTEGER) -> LARGE_INTEGER;
}

/// Read the system clock as a Windows FILETIME (100-ns ticks since 1601-01-01).
///
/// On AMD64, `KeQuerySystemTime` is a FORCEINLINE in wdm.h that reads
/// `KUSER_SHARED_DATA.SystemTime` via a seqlock — it is NOT exported from
/// ntoskrnl.lib. We replicate the same logic here.
///
/// `KUSER_SHARED_DATA` is mapped at a fixed virtual address (`0xFFFFF78000000000`)
/// in every 64-bit Windows process and kernel context. `SystemTime` (a
/// `KSYSTEM_TIME { LowPart: u32, High1Time: i32, High2Time: i32 }`) lives at
/// offset `0x14` from that base.
#[allow(non_snake_case)]
pub fn KeQuerySystemTime() -> u64 {
    // KUSER_SHARED_DATA base + offsetof(SystemTime) = 0xFFFFF78000000000 + 0x14
    const SYSTEM_TIME_PTR: *const u32 = 0xFFFF_F780_0000_0014usize as *const u32;
    // KSYSTEM_TIME layout: [0] LowPart, [1] High1Time, [2] High2Time (each 4 bytes)
    loop {
        let h1 = unsafe { SYSTEM_TIME_PTR.add(1).read_volatile() } as u64;
        let lo = unsafe { SYSTEM_TIME_PTR.add(0).read_volatile() } as u64;
        let h2 = unsafe { SYSTEM_TIME_PTR.add(2).read_volatile() } as u64;
        if h1 == h2 {
            return (h1 << 32) | lo;
        }
    }
}

// MDL flag bits (from wdm.h).
const MDL_MAPPED_TO_SYSTEM_VA: i16 = 0x0001;
const MDL_SOURCE_IS_NONPAGED_POOL: i16 = 0x0004;
// MM_PAGE_PRIORITY::NormalPagePriority for MmMapLockedPagesSpecifyCache.
const NORMAL_PAGE_PRIORITY: u32 = 16;

/// Returns a pointer to the caller's I/O stack location in the specified IRP.
///
/// Equivalent to the `IoGetCurrentIrpStackLocation` macro in ntddk.h.
#[allow(non_snake_case)]
pub unsafe fn IoGetCurrentIrpStackLocation(irp: PIRP) -> PIO_STACK_LOCATION {
    (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation
}

/// Returns a pointer to the next-lower driver's I/O stack location.
///
/// Equivalent to `IoGetNextIrpStackLocation` in ntddk.h.
#[allow(non_snake_case)]
pub unsafe fn IoGetNextIrpStackLocation(irp: PIRP) -> PIO_STACK_LOCATION {
    (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation
        .offset(-1)
}

/// Returns a kernel system-space virtual address for the MDL's pages, mapping
/// them if necessary. Returns null on mapping failure.
///
/// Equivalent to `MmGetSystemAddressForMdlSafe` in wdm.h: if the MDL is already
/// mapped to a system VA (or backed by non-paged pool), returns the cached
/// `MappedSystemVa`; otherwise maps it via `MmMapLockedPagesSpecifyCache`.
///
/// # Safety
/// `mdl` must be a valid, page-locked MDL. Caller must be at IRQL <= APC_LEVEL
/// for the mapping path.
#[allow(non_snake_case)]
pub unsafe fn MmGetSystemAddressForMdlSafe(mdl: PMDL) -> *mut c_void {
    if mdl.is_null() {
        return core::ptr::null_mut();
    }
    let flags = (*mdl).MdlFlags;
    if flags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL) != 0 {
        return (*mdl).MappedSystemVa;
    }
    // Not yet mapped — map into system space (MmCached, NormalPagePriority).
    MmMapLockedPagesSpecifyCache(
        mdl,
        0, // KernelMode
        1, // MmCached
        core::ptr::null_mut(),
        0,
        NORMAL_PAGE_PRIORITY,
    )
}

/// Atomically replaces the IRP's cancel routine and returns the previous one.
///
/// Equivalent to `IoSetCancelRoutine` in ntddk.h (which is a FORCEINLINE using
/// `InterlockedExchangePointer` on `Irp->CancelRoutine`).
///
/// # Safety
/// `irp` must be a valid, initialised IRP. The caller is responsible for
/// correct cancel-routine protocol (check `Irp->Cancel` after clearing).
#[allow(non_snake_case)]
pub unsafe fn IoSetCancelRoutine(irp: PIRP, routine: DRIVER_CANCEL) -> DRIVER_CANCEL {
    let new_ptr = match routine {
        Some(r) => r as *mut c_void,
        None => core::ptr::null_mut(),
    };
    let slot = &raw mut (*irp).CancelRoutine as *mut _ as *mut AtomicPtr<c_void>;
    let old_ptr = (*slot).swap(new_ptr, Ordering::SeqCst);
    if old_ptr.is_null() {
        None
    } else {
        Some(core::mem::transmute(old_ptr))
    }
}
