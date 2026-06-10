//! Tracks every volume currently attached to the driver (OS via handover, data
//! via IOCTL).

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use spin::Mutex;
use vck_common::{types::Guid, EncryptedOffsetStore, SectorIo, VckResult};
use wdk_sys::{DEVICE_OBJECT, DRIVER_OBJECT};

use crate::{crypto::aes_xts::AesXtsCipher, offset::engine::EncryptionEngine, provider::IoConfig};

/// Boot-time ACPI handover essentials, decoded once at `DriverEntry`.
///
/// The sample-specific payload type lives in `vck-sample-common`; the framework
/// only needs these two generic fields to identify the OS volume (by GPT
/// partition GUID) and decrypt its footer metadata (with the VMK).
#[derive(Clone)]
pub struct HandoverInfo {
    /// GPT partition unique GUID of the OS volume to auto-attach.
    pub partition_guid: Guid,
    /// Key that decrypts the volume footer metadata to recover the FVEK.
    pub vmk: Vec<u8>,
}

/// Process-wide pointer to the single `VolumeAttachRegistry`. Set once at
/// `DriverEntry` via [`set_global_registry`] so the filter's PnP work item (a C
/// callback that only receives a device object) can reach the registry to look
/// up the handover and insert the auto-attached OS volume.
static GLOBAL_REGISTRY: AtomicPtr<VolumeAttachRegistry> = AtomicPtr::new(null_mut());

/// Record the process-wide registry pointer. `registry` must outlive the driver
/// (a `'static`).
pub fn set_global_registry(registry: &'static VolumeAttachRegistry) {
    GLOBAL_REGISTRY.store(
        registry as *const VolumeAttachRegistry as *mut VolumeAttachRegistry,
        Ordering::Release,
    );
}

/// Borrow the process-wide registry, if set.
pub fn global_registry() -> Option<&'static VolumeAttachRegistry> {
    let ptr = GLOBAL_REGISTRY.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // Safety: set_global_registry only ever stores a 'static reference.
        Some(unsafe { &*ptr })
    }
}

/// Entry in the AddDevice-time filter map.
pub struct PdoFilterEntry {
    pub pdo: *mut DEVICE_OBJECT,
    pub filter_do: *mut DEVICE_OBJECT,
    pub lower_do: *mut DEVICE_OBJECT,
    /// NT object name of the PDO (e.g. `\Device\HarddiskVolume5`).
    pub pdo_name: alloc::string::String,
}
unsafe impl Send for PdoFilterEntry {}
unsafe impl Sync for PdoFilterEntry {}

pub struct VolumeAttachRegistry {
    // volume_path (NT device path) -> AttachedVolume
    entries: Mutex<BTreeMap<String, Arc<AttachedVolume>>>,
    // Set once at DriverEntry; needed to create filter device objects.
    driver_object: AtomicPtr<DRIVER_OBJECT>,
    /// PDO → filter mapping built by add_device. Used by PREPARE to find the
    /// pre-attached filter without relying on device stack walking (which breaks
    /// when NTFS mounts via VPB rather than IoAttachDeviceToDeviceStackSafe).
    pdo_filters: Mutex<alloc::vec::Vec<PdoFilterEntry>>,
    /// Boot ACPI handover (None if no loader published a `VCKD` table). Set once
    /// at DriverEntry; read by the filter PnP path to auto-attach the OS volume.
    handover: Mutex<Option<HandoverInfo>>,
}

pub struct AttachedVolume {
    pub volume_path: String,
    pub sector_size: u32,
    pub io_config: IoConfig,
    pub encryption: Mutex<EncryptionEngine>,
    pub offset_store: Arc<dyn EncryptedOffsetStore>,
    pub attach_source: AttachSource,
    /// Filter device object attached above this volume (null if none yet).
    pub filter_device: AtomicPtr<DEVICE_OBJECT>,
    /// AES-XTS cipher for the background sweep (present on the high-level path).
    pub cipher: Option<AesXtsCipher>,
    /// Raw sector I/O for the background sweep. After `attach_filter` this is
    /// replaced (via `Mutex`) with a handle opened directly against the lower
    /// device object, so sweep I/O bypasses our filter entirely.
    pub sweep_io: Mutex<Arc<dyn SectorIo>>,
    /// Lock-free snapshot of the current encrypted boundary (data-region-relative
    /// sector). Updated by the sweep after each batch via `Relaxed` store;
    /// the filter's completion routines read this with `Acquire` to avoid
    /// holding `encryption` (a spinlock) during IRP completion — doing so would
    /// deadlock when the sweep holds the lock while its I/O passes through the
    /// filter.
    pub encrypted_boundary: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachSource {
    /// OS Volume: auto-attached from the ACPI handover.
    Handover,
    /// Data Volume: attached at runtime via IOCTL_JVCK_ATTACH.
    Ioctl,
}

impl VolumeAttachRegistry {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            driver_object: AtomicPtr::new(null_mut()),
            pdo_filters: Mutex::new(alloc::vec::Vec::new()),
            handover: Mutex::new(None),
        }
    }

    /// Store the boot ACPI handover essentials (called once at DriverEntry).
    pub fn set_handover(&self, info: HandoverInfo) {
        crate::driver_println!(
            "registry: handover set partition_guid={}", info.partition_guid
        );
        *self.handover.lock() = Some(info);
    }

    /// Clone the stored handover, if a loader published one.
    pub fn handover(&self) -> Option<HandoverInfo> {
        self.handover.lock().clone()
    }

    /// Called from add_device to record the PDO → filter mapping.
    pub fn add_pdo_filter(
        &self,
        pdo: *mut DEVICE_OBJECT,
        filter_do: *mut DEVICE_OBJECT,
        lower_do: *mut DEVICE_OBJECT,
        pdo_name: alloc::string::String,
    ) {
        crate::driver_println!("add_pdo_filter: name={} filter={:p}", pdo_name, filter_do);
        self.pdo_filters.lock().push(PdoFilterEntry { pdo, filter_do, lower_do, pdo_name });
    }

    /// Return the recorded PDO object name for the given filter device object
    /// (set by add_device). Used as the registry key for the handover OS volume.
    pub fn pdo_name_for_filter(&self, filter_do: *mut DEVICE_OBJECT) -> Option<String> {
        let map = self.pdo_filters.lock();
        for e in map.iter() {
            if e.filter_do == filter_do && !e.pdo_name.is_empty() {
                return Some(e.pdo_name.clone());
            }
        }
        None
    }

    /// Look up the filter by device pointer address (fallback).
    pub fn find_pdo_filter(&self, dev: *mut DEVICE_OBJECT) -> Option<(*mut DEVICE_OBJECT, *mut DEVICE_OBJECT)> {
        let map = self.pdo_filters.lock();
        for e in map.iter() {
            if e.pdo == dev || e.lower_do == dev {
                return Some((e.filter_do, e.lower_do));
            }
        }
        None
    }

    /// Look up the filter by PDO name (e.g. `\Device\HarddiskVolume5`).
    /// This is the primary lookup since Volume class PDOs may not match
    /// the device object returned by IoGetDeviceObjectPointer.
    pub fn find_pdo_filter_by_name(&self, nt_path: &str) -> Option<(*mut DEVICE_OBJECT, *mut DEVICE_OBJECT)> {
        // Normalize: trim trailing slashes and case-fold.
        let query = nt_path.trim_end_matches('\\').to_ascii_lowercase();
        let map = self.pdo_filters.lock();
        for e in map.iter() {
            let name = e.pdo_name.trim_end_matches('\\').to_ascii_lowercase();
            if name == query {
                return Some((e.filter_do, e.lower_do));
            }
        }
        None
    }

    /// Record the WDM driver object (set once at DriverEntry).
    pub fn set_driver_object(&self, driver: *mut DRIVER_OBJECT) {
        self.driver_object.store(driver, Ordering::Release);
    }

    pub fn driver_object(&self) -> *mut DRIVER_OBJECT {
        self.driver_object.load(Ordering::Acquire)
    }

    pub fn insert(&self, volume: Arc<AttachedVolume>) {
        self.entries
            .lock()
            .insert(volume.volume_path.clone(), volume);
    }

    pub fn get(&self, volume_path: &str) -> Option<Arc<AttachedVolume>> {
        self.entries.lock().get(volume_path).cloned()
    }

    pub fn remove(&self, volume_path: &str) -> Option<Arc<AttachedVolume>> {
        self.entries.lock().remove(volume_path)
    }

    /// Snapshot of all attached volumes (for the sweep worker to iterate).
    pub fn all(&self) -> Vec<Arc<AttachedVolume>> {
        self.entries.lock().values().cloned().collect()
    }

    /// True if any attached OS (handover) volume has at least one encrypted
    /// sector. Such a volume must not be detached and the driver must not unload
    /// (doing so would leave the live OS volume reading ciphertext).
    pub fn has_encrypted_os_volume(&self) -> bool {
        self.entries
            .lock()
            .values()
            .any(|v| v.is_os_volume() && v.has_encrypted_data())
    }
}

impl AttachedVolume {
    /// True when this volume was attached via the OS boot ACPI handover (i.e. it
    /// is the system/OS volume), as opposed to a runtime IOCTL-attached data volume.
    pub fn is_os_volume(&self) -> bool {
        matches!(self.attach_source, AttachSource::Handover)
    }

    /// True when at least one sector has been encrypted (boundary advanced past 0).
    pub fn has_encrypted_data(&self) -> bool {
        self.encrypted_boundary.load(Ordering::Acquire) > 0
    }

    pub fn offset_sector(&self) -> u64 {
        match &self.io_config {
            IoConfig::Passthrough => 0,
            IoConfig::AesXts { offset_sector, .. } | IoConfig::Custom { offset_sector, .. } => {
                *offset_sector
            }
        }
    }

    /// Number of sectors in the data (encryptable) region — i.e. the volume size
    /// the OS should see, with the header/footer metadata regions excluded.
    pub fn data_sectors(&self) -> u64 {
        match &self.io_config {
            IoConfig::Passthrough => 0,
            IoConfig::AesXts {
                encrypted_offset, ..
            }
            | IoConfig::Custom {
                encrypted_offset, ..
            } => encrypted_offset.total_sectors,
        }
    }

    /// Update the lock-free boundary cache after the sweep advances. Called by
    /// `sweep_step` AFTER the encryption lock is released.
    pub fn sync_boundary(&self) {
        let boundary = self.encryption.lock().encrypted_boundary();
        self.encrypted_boundary.store(boundary, Ordering::Release);
    }

    /// Run one batch of the encrypt/decrypt sweep. Returns `Ok(true)` if this
    /// volume still has work pending, `Ok(false)` when idle (or not high-level).
    pub fn sweep_step(&self, batch_sectors: u64) -> VckResult<bool> {
        let cipher = match self.cipher.as_ref() {
            Some(cipher) => cipher,
            None => return Ok(false),
        };
        let io = self.sweep_io.lock().clone();
        let result = {
            let mut engine = self.encryption.lock();
            engine.progress_step(io.as_ref(), cipher, self.offset_store.as_ref(), batch_sectors)
        }; // lock released here before sync_boundary
        if result.is_ok() {
            self.sync_boundary();
        }
        result
    }
}

impl Default for VolumeAttachRegistry {
    fn default() -> Self {
        Self::new()
    }
}
