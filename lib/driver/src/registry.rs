//! Tracks every volume currently attached to the driver (OS via handover, data
//! via IOCTL).

use alloc::{collections::BTreeMap, string::String, sync::Arc};

use spin::Mutex;
use vck_common::EncryptedOffsetStore;

use crate::{offset::engine::EncryptionEngine, provider::IoConfig};

pub struct VolumeAttachRegistry {
    // volume_path (NT device path) -> AttachedVolume
    entries: Mutex<BTreeMap<String, Arc<AttachedVolume>>>,
}

pub struct AttachedVolume {
    pub volume_path: String,
    pub io_config: IoConfig,
    pub encryption: Mutex<EncryptionEngine>,
    pub offset_store: Arc<dyn EncryptedOffsetStore>,
    pub attach_source: AttachSource,
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
}

impl Default for VolumeAttachRegistry {
    fn default() -> Self {
        Self::new()
    }
}
