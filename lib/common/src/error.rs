use alloc::string::String;
use core::fmt::{Display, Formatter};

pub type VckResult<T> = core::result::Result<T, VckError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VckError {
    InvalidData(&'static str),
    ValidationFailed(&'static str),
    Unsupported(&'static str),
    NotFound(&'static str),
    PermissionDenied(&'static str),
    SizeMismatch { expected: usize, actual: usize },
    SignatureMismatch,
    ChecksumMismatch,
    CryptoFailed(&'static str),
    MsgpackEncode(String),
    MsgpackDecode(String),
    Io(String),
}

impl Display for VckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidData(msg) => write!(f, "invalid data: {msg}"),
            Self::ValidationFailed(msg) => write!(f, "validation failed: {msg}"),
            Self::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::PermissionDenied(msg) => write!(f, "permission denied: {msg}"),
            Self::SizeMismatch { expected, actual } => {
                write!(f, "size mismatch: expected {expected}, got {actual}")
            }
            Self::SignatureMismatch => f.write_str("signature mismatch"),
            Self::ChecksumMismatch => f.write_str("checksum mismatch"),
            Self::CryptoFailed(msg) => write!(f, "cryptography failed: {msg}"),
            Self::MsgpackEncode(msg) => write!(f, "msgpack encode failed: {msg}"),
            Self::MsgpackDecode(msg) => write!(f, "msgpack decode failed: {msg}"),
            Self::Io(msg) => write!(f, "io failed: {msg}"),
        }
    }
}

impl core::error::Error for VckError {}
