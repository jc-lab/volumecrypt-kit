//! Tracks every volume currently attached to the driver (OS via handover, data
//! via IOCTL).

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};

use spin::Mutex;
use vck_common::{EncryptedOffsetStore, SectorIo, VckResult};

use crate::{crypto::aes_xts::AesXtsCipher, offset::engine::EncryptionEngine, provider::IoConfig};

pub struct VolumeAttachRegistry {
    // volume_path (NT device path) -> AttachedVolume
    entries: Mutex<BTreeMap<String, Arc<AttachedVolume>>>,
}

pub struct AttachedVolume {
    pub volume_path: String,
    pub sector_size: u32,
    pub io_config: IoConfig,
    pub encryption: Mutex<EncryptionEngine>,
    pub offset_store: Arc<dyn EncryptedOffsetStore>,
    pub attach_source: AttachSource,
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
        }
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
