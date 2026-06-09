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
/// The driver only ever OPENS existing JVCK metadata: first-time metadata
/// creation (FVEK/volume-id generation + footer write over an extended-DASD
/// handle) is performed by the user-space SDK before attach. So the FVEK and
/// volume id are not part of this request; the layout fields are advisory and
/// are authoritatively recovered from the on-disk header.
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
