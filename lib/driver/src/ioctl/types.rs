//! msgpack request/response structs. Field names + tags MUST match `sdk/types.go`.
//!
//! `state` is wired as an integer (see Go `EncryptionState`): 0=Idle,
//! 1=Encrypting, 2=Decrypting, 3=Paused.

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

pub const STATE_IDLE: i32 = 0;
pub const STATE_ENCRYPTING: i32 = 1;
pub const STATE_DECRYPTING: i32 = 2;
pub const STATE_PAUSED: i32 = 3;

/// IOCTL_JVCK_PREPARE request (phase 1).
///
/// Attaches the volume filter and activates size hiding so NTFS does not place
/// its VBR backup in the metadata region. After this returns, the app writes
/// JVCK metadata (via EnsureJvckMetadata / FSCTL_ALLOW_EXTENDED_DASD_IO) and
/// then calls IOCTL_JVCK_ATTACH to complete encryption setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JvckVolumePrepareReq {
    pub volume_path: String,
    /// NT kernel device path (e.g. `\Device\HarddiskVolume3`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nt_device_path: String,
    #[serde(default)]
    pub use_header: u32,
    #[serde(default)]
    pub use_footer: u32,
    #[serde(default)]
    pub metadata_size: u32,
    /// VMK used to decrypt the metadata_block and recover the FVEK. Required
    /// when metadata_block is non-empty (driver needs FVEK to encrypt sector 0).
    #[serde(default, with = "serde_bytes")]
    pub vmk: Vec<u8>,
    /// Pre-encoded JVCK Metadata block (512 bytes, encoded with encrypted_offset=1
    /// so the sweep starts from sector 1). Written to every replica LBA while locked.
    /// Empty means skip writing (re-attach to an already-prepared volume).
    #[serde(default, with = "serde_bytes")]
    pub metadata_block: Vec<u8>,
}

/// IOCTL_JVCK_PREPARE response.
///
/// When VMK was provided and metadata_block was non-empty, the driver
/// completes full attach (cipher, sweep setup) and the response contains the
/// final encryption geometry — same semantics as the old IOCTL_JVCK_ATTACH
/// response, so the app can treat PREPARE as the single IOCTL that does
/// everything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JvckVolumePrepareResp {
    pub offset_sector: u64,
    pub data_sectors: u64,
    pub sector_size: u32,
    /// Raw partition path (e.g. `\Device\Harddisk0\Partition1`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw_partition_path: String,
    /// Raw disk path (e.g. `\Device\Harddisk0\DR0`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw_disk_path: String,
    /// Partition start LBA on the physical disk.
    #[serde(default)]
    pub partition_start_lba: u64,
    /// true when the volume is fully attached (cipher + sweep ready).
    /// false when PREPARE was called without VMK (provisional-only mode).
    #[serde(default)]
    pub fully_attached: bool,
}

/// IOCTL_JVCK_ATTACH request.
///
/// The driver only ever OPENS existing JVCK metadata. When `nt_device_path` is
/// present (e.g. `\Device\HarddiskVolume3`), the driver uses it for
/// ZwCreateFile/IoGetDeviceObjectPointer instead of the Win32 volume_path.
/// This NT path works even when the filesystem is transiently dismounted during
/// the lock → attach-below-FSD → dismount → unlock sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JvckVolumeAttachReq {
    pub volume_path: String,
    // `vmk` is msgpack BIN on the wire (Go encodes `[]byte` as bin), so it goes
    // through serde_bytes rather than the default Vec<u8> = sequence.
    #[serde(with = "serde_bytes")]
    pub vmk: Vec<u8>,
    #[serde(default)]
    pub use_header: u32,
    #[serde(default)]
    pub use_footer: u32,
    #[serde(default)]
    pub metadata_size: u32,
    /// NT kernel device path (e.g. `\Device\HarddiskVolume3`). When non-empty,
    /// used instead of volume_path for kernel-mode I/O so access works even if
    /// the filesystem is transiently dismounted.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nt_device_path: String,
    /// Raw partition path (e.g. `\Device\Harddisk0\Partition1`) returned by
    /// IOCTL_JVCK_PREPARE. Used for sweep_io to bypass NTFS write protection.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw_partition_path: String,
}

/// IOCTL_JVCK_ATTACH response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JvckVolumeAttachResp {
    pub offset_sector: u64,
    pub total_sectors: u64,
    pub sector_size: u32,
}

/// Shared request carrying only a volume path (status/pause/progress/detach).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeRequest {
    pub volume_path: String,
}

/// IOCTL_VCK_GET_STATUS response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeStatus {
    pub volume_path: String,
    pub state: i32,
    pub encrypted_sector: u64,
    pub total_sectors: u64,
    pub sector_size: u32,
    pub is_attached: bool,
    /// true when the filter was placed BELOW the FSD via AddDevice (correct
    /// position for transparent encryption). false when attached above the FSD
    /// or when the driver needs a reboot to activate AddDevice.
    #[serde(default)]
    pub filter_below_fsd: bool,
}

/// IOCTL_VCK_GET_PROGRESS response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub encrypted_sector: u64,
    pub total_sectors: u64,
    pub state: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}
