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

/// IOCTL_JVCK_ATTACH request.
///
/// `fvek_key1`/`fvek_key2`/`volume_id` are only used on first-time encryption
/// (when no metadata exists yet); the user-space app generates them with a
/// CSPRNG. On re-attach they are ignored (recovered from existing metadata),
/// so the app may send empty slices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JvckVolumeAttachReq {
    pub volume_path: String,
    // Byte fields are msgpack BIN on the wire (Go encodes `[]byte` as bin), so
    // they go through serde_bytes rather than the default Vec<u8> = sequence.
    #[serde(with = "serde_bytes")]
    pub vmk: Vec<u8>,
    pub use_header: u32,
    pub use_footer: u32,
    pub metadata_size: u32,
    #[serde(default, with = "serde_bytes")]
    pub fvek_key1: Vec<u8>,
    #[serde(default, with = "serde_bytes")]
    pub fvek_key2: Vec<u8>,
    #[serde(default, with = "serde_bytes")]
    pub volume_id: Vec<u8>,
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
