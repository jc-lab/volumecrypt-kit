// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Boot-time OS-volume auto-attach (ACPI handover path).
//!
//! boot flow: the filter is attached unbound at `AddDevice`, and the actual
//! "mount" (read footer metadata, recover the FVEK, bind the cipher) is
//! deferred until **after** `IRP_MN_START_DEVICE` completes — only then
//! is synchronous block I/O to the lower device safe.
//!
//! [`on_start_device_completed`] is installed as the START completion routine by
//! the filter dispatch ([`crate::filter::handle_filter_irp`]). When the device
//! has started it runs [`try_mount_handover_volume`] at PASSIVE_LEVEL (directly
//! if already there, else via an `IoWorkItem`), which:
//!
//!   1. reads the lower device's GPT partition GUID and matches it against the
//!      handover (`VCKD` ACPI table) — non-matching devices are left untouched;
//!   2. opens the footer metadata with the handover VMK to recover the FVEK,
//!      data-region geometry, and persisted encrypted offset;
//!   3. builds an `AttachSource::Handover` volume and binds it to the filter.
//!
//! With no loader (no `VCKD` table) the registry handover is `None` and this is
//! a no-op, so data-volume behaviour is unaffected.

use alloc::sync::Arc;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64};

use spin::Mutex;
use vck_common::{
    jvck::JvckMetadataStore, EncryptedOffset, EncryptedOffsetStore, SectorIo,
};
use wdk_sys::{
    ntddk::{
        ExAllocatePool2, ExFreePool, IoAllocateWorkItem, IoFreeWorkItem, IoQueueWorkItem,
        KeGetCurrentIrql, KeInitializeEvent, KeSetEvent, KeWaitForSingleObject,
    },
    KEVENT, NTSTATUS, PDEVICE_OBJECT, PIO_WORKITEM, PIRP,
    SL_PENDING_RETURNED,
    _EVENT_TYPE::NotificationEvent,
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
    _WORK_QUEUE_TYPE::DelayedWorkQueue,
};

use crate::{
    device::DeviceExtension,
    io::LowerDeviceIo,
    offset::engine::EncryptionEngine,
    provider::IoConfig,
    registry::{global_registry, AttachSource, AttachedVolume},
};

const STATUS_CONTINUE_COMPLETION: NTSTATUS = 0;
const PASSIVE_LEVEL: u8 = 0;
const POOL_FLAG_NON_PAGED: u64 = 0x0000_0000_0000_0040;
const VCK_POOL_TAG: u32 = u32::from_le_bytes(*b"VCKM");

unsafe fn current_sl(irp: PIRP) -> wdk_sys::PIO_STACK_LOCATION {
    (*irp).Tail.Overlay.__bindgen_anon_2.__bindgen_anon_1.CurrentStackLocation
}

// ---------------------------------------------------------------------------
// START_DEVICE completion + deferred work item
// ---------------------------------------------------------------------------

/// Heap context for the deferred (non-PASSIVE) mount work item.
#[repr(C)]
struct StartWorkCtx {
    filter_do: PDEVICE_OBJECT,
    done: KEVENT,
}

/// Filter completion routine for `IRP_MN_START_DEVICE` (installed by the filter
/// dispatch). Runs the handover mount once the lower device has started.
///
/// # Safety
/// Called by the I/O manager with the filter device object passed as `context`.
pub unsafe extern "C" fn on_start_device_completed(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
    context: *mut c_void,
) -> NTSTATUS {
    let filter_do = context as PDEVICE_OBJECT;

    // Propagate the pending bit up the stack if the lower driver pended.
    if (*irp).PendingReturned != 0 {
        (*current_sl(irp)).Control |= SL_PENDING_RETURNED as u8;
    }

    if KeGetCurrentIrql() == PASSIVE_LEVEL {
        try_mount_handover_volume(filter_do);
    } else {
        // Defer to a PASSIVE_LEVEL work item and block until it finishes, so the
        // OS volume is fully bound (cipher active) before START propagates up —
        // any read of an encrypted sector before binding would return ciphertext.
        let wi: PIO_WORKITEM = IoAllocateWorkItem(filter_do);
        if wi.is_null() {
            crate::vck_log!("handover_mount: IoAllocateWorkItem failed; leaving unbound");
            return STATUS_CONTINUE_COMPLETION;
        }
        let ctx = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            core::mem::size_of::<StartWorkCtx>() as u64,
            VCK_POOL_TAG,
        ) as *mut StartWorkCtx;
        if ctx.is_null() {
            IoFreeWorkItem(wi);
            crate::vck_log!("handover_mount: work ctx alloc failed; leaving unbound");
            return STATUS_CONTINUE_COMPLETION;
        }
        (*ctx).filter_do = filter_do;
        KeInitializeEvent(&mut (*ctx).done, NotificationEvent, 0);
        IoQueueWorkItem(wi, Some(mount_work_routine), DelayedWorkQueue, ctx.cast());
        let _ = KeWaitForSingleObject(
            (&mut (*ctx).done as *mut KEVENT).cast::<c_void>(),
            Executive,
            KernelMode as i8,
            0,
            null_mut(),
        );
        IoFreeWorkItem(wi);
        ExFreePool(ctx.cast());
    }

    STATUS_CONTINUE_COMPLETION
}

/// `IoWorkItem` routine: run the mount at PASSIVE_LEVEL, then signal completion.
unsafe extern "C" fn mount_work_routine(_device: PDEVICE_OBJECT, context: *mut c_void) {
    let ctx = &mut *(context as *mut StartWorkCtx);
    try_mount_handover_volume(ctx.filter_do);
    KeSetEvent(&mut ctx.done, 0, 0);
}

// ---------------------------------------------------------------------------
// Mount
// ---------------------------------------------------------------------------

/// Attempt to auto-attach the OS volume sitting below `filter_do` using the boot
/// ACPI handover. No-op (best-effort) when there is no handover, the partition
/// GUID does not match, the volume is already bound, or the footer cannot be
/// decrypted — failures here must never block the device from starting.
///
/// # Safety
/// `filter_do` must be one of this driver's filter device objects, called at
/// PASSIVE_LEVEL after the lower device has started.
pub unsafe fn try_mount_handover_volume(filter_do: PDEVICE_OBJECT) {
    let registry = match global_registry() {
        Some(r) => r,
        None => return,
    };
    let handover = match registry.handover() {
        Some(h) => h,
        None => return, // No loader / no VCKD table — nothing to auto-attach.
    };

    let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
    if !(*ext).volume.is_null() {
        return; // Already bound (START may fire more than once).
    }
    let lower_do = (*ext).lower_device;
    if lower_do.is_null() {
        return;
    }

    // Probe the raw lower device (bypassing our filter) over IRP IOCTLs. We use
    // LowerDeviceIo (IoBuildDeviceIoControlRequest) rather than a device handle:
    // an ObOpenObjectByPointer handle rejects ZwDeviceIoControlFile with
    // OBJECT_TYPE_MISMATCH.
    let mut footer_io = LowerDeviceIo::new(lower_do, 0, 0);
    if let Err(e) = footer_io.query_geometry() {
        crate::vck_log!("handover_mount: geometry probe failed: {}", e);
        return;
    }

    // Match this device's GPT partition GUID against the handover target.
    match footer_io.read_gpt_partition_id() {
        Ok(guid) => {
            if guid != handover.partition_guid {
                crate::vck_log!(
                    "handover_mount: partition {} != target {}, skipping",
                    guid, handover.partition_guid
                );
                return;
            }
            crate::vck_log!("handover_mount: OS volume matched ({})", guid);
        }
        Err(e) => {
            crate::vck_log!("handover_mount: partition id read failed: {}", e);
            return;
        }
    }

    // Decrypt the footer metadata with the VMK to recover keys + geometry.
    // Footer I/O goes straight to the lower device, bypassing our filter.
    let store = match JvckMetadataStore::open(footer_io, &handover.vmk) {
        Ok(s) => s,
        Err(e) => {
            crate::vck_log!("handover_mount: footer metadata open failed: {}", e);
            return;
        }
    };
    let offset_sector = store.offset_sector();
    let data_sectors = store.data_sector_count();
    let store_bps = store.sector_size();
    let persisted_offset = match store.load_offset() {
        Ok(o) => o,
        Err(e) => {
            crate::vck_log!("handover_mount: load_offset failed: {}", e);
            return;
        }
    };
    let encrypted_offset = EncryptedOffset {
        sector: persisted_offset,
        total_sectors: data_sectors,
    };
    let (key1, key2) = store.fvek_keys();
    let (key1, key2) = (*key1, *key2);
    let cipher = match crate::crypto::build_volume_cipher(store.header(), key1, key2) {
        Ok(c) => c,
        Err(e) => {
            crate::vck_log!("handover_mount: cipher init failed: {}", e);
            return;
        }
    };

    let offset_store: Arc<dyn EncryptedOffsetStore> = Arc::new(store);
    let io_config = IoConfig::AesXts {
        key1,
        key2,
        offset_sector,
        encrypted_offset: encrypted_offset.clone(),
        offset_store: offset_store.clone(),
    };
    // sweep_io targets the lower device directly so the background sweep never
    // re-enters our own filter.
    let sweep_io: Arc<dyn SectorIo> =
        Arc::new(LowerDeviceIo::new(lower_do, store_bps, data_sectors));

    // Registry key: the lower device's NT object name (stable + unique).
    let volume_path = registry
        .pdo_name_for_filter(filter_do)
        .unwrap_or_else(|| alloc::format!("\\Device\\HandoverVolume[{:p}]", lower_do));

    let initial_boundary = encrypted_offset.sector;
    let volume = Arc::new(AttachedVolume {
        volume_path: volume_path.clone(),
        sector_size: store_bps,
        io_config,
        encryption: Mutex::new(EncryptionEngine::new(offset_sector, encrypted_offset)),
        offset_store,
        attach_source: AttachSource::Handover,
        filter_device: AtomicPtr::new(filter_do),
        cipher: Some(cipher),
        sweep_io: Mutex::new(sweep_io),
        encrypted_boundary: AtomicU64::new(initial_boundary),
    });
    registry.insert(volume.clone());

    // Resume the sweep across reboot in the PERSISTED direction: the footer
    // metadata records both the boundary and the sweep state (encrypt/decrypt),
    // so `resume` reads `store.load_state()` and continues encrypting OR
    // decrypting (a decrypt that was in progress must not flip back to encrypt).
    // No-op once there is nothing left to do in that direction. Set the state
    // BEFORE binding so the per-volume thread sweeps on start.
    volume.encryption.lock().resume(&*volume.offset_store);

    crate::filter::filter_bind_volume(filter_do, volume.clone());
    crate::vck_log!(
        "handover_mount: OS volume bound path={} offset_sector={} data_sectors={} boundary={}",
        volume_path, offset_sector, data_sectors, initial_boundary
    );
    unsafe { crate::filter::volume_thread::wake_for(&volume) };
}
