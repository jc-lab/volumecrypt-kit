//! Tracks every volume currently attached to the driver (OS via handover, data
//! via IOCTL).

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use spin::Mutex;
use vck_common::{EncryptedOffsetStore, SectorIo, VckResult};
use wdk_sys::{DEVICE_OBJECT, DRIVER_OBJECT};

use crate::{crypto::aes_xts::AesXtsCipher, offset::engine::EncryptionEngine, provider::IoConfig};

pub struct VolumeAttachRegistry {
    // volume_path (NT device path) -> AttachedVolume
    entries: Mutex<BTreeMap<String, Arc<AttachedVolume>>>,
    // Set once at DriverEntry; needed to create filter device objects.
    driver_object: AtomicPtr<DRIVER_OBJECT>,
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
    /// Raw volume sector I/O used by the sweep to read plaintext / write
    /// ciphertext. Currently the volume device itself; once a transparent filter
    /// is attached this must be the lower device.
    pub sweep_io: Arc<dyn SectorIo>,
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
        }
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
}

impl AttachedVolume {
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

    /// Run one batch of the encrypt/decrypt sweep. Returns `Ok(true)` if this
    /// volume still has work pending, `Ok(false)` when idle (or not high-level).
    pub fn sweep_step(&self, batch_sectors: u64) -> VckResult<bool> {
        let cipher = match self.cipher.as_ref() {
            Some(cipher) => cipher,
            None => return Ok(false),
        };
        let mut engine = self.encryption.lock();
        engine.progress_step(
            self.sweep_io.as_ref(),
            cipher,
            self.offset_store.as_ref(),
            batch_sectors,
        )
    }
}

impl Default for VolumeAttachRegistry {
    fn default() -> Self {
        Self::new()
    }
}
