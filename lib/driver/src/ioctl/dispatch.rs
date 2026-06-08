//! IRP_MJ_DEVICE_CONTROL handler. Authorizes, then routes by IOCTL code.
//!
//! GET_PROGRESS is non-blocking: it returns the current snapshot immediately.

use vck_common::{VckError, VckResult};

use crate::{
    ioctl::codes::*,
    provider::{IoctlAuthContext, IoctlAuthorization},
};

/// Serialized msgpack response buffer to copy back to the caller.
use alloc::vec::Vec;
pub type IoctlResponse = Vec<u8>;

/// Authorize then dispatch. `auth` is the sample-provided policy; `input` is the
/// caller's msgpack request buffer.
pub fn dispatch_ioctl<A: IoctlAuthorization>(
    auth: &A,
    ctx: &IoctlAuthContext<'_>,
    input: &[u8],
) -> VckResult<IoctlResponse> {
    auth.authorize(ctx)?;
    let _ = input;
    match ctx.ioctl_code {
        IOCTL_VCK_GET_STATUS => handle_get_status(input),
        IOCTL_VCK_START_ENCRYPT => handle_start_encrypt(input),
        IOCTL_VCK_START_DECRYPT => handle_start_decrypt(input),
        IOCTL_VCK_GET_PROGRESS => handle_get_progress(input),
        IOCTL_VCK_PAUSE => handle_pause(input),
        IOCTL_JVCK_ATTACH => handle_jvck_attach(input),
        IOCTL_VCK_DETACH => handle_detach(input),
        _ => Err(VckError::Unsupported("unknown IOCTL code")),
    }
}

fn handle_get_status(_input: &[u8]) -> VckResult<IoctlResponse> {
    todo!("decode VolumeRequest, look up registry, encode VolumeStatus")
}
fn handle_start_encrypt(_input: &[u8]) -> VckResult<IoctlResponse> {
    todo!("spawn EncryptionEngine::progress_encryption, return immediately")
}
fn handle_start_decrypt(_input: &[u8]) -> VckResult<IoctlResponse> {
    todo!("spawn progressive decryption")
}
fn handle_get_progress(_input: &[u8]) -> VckResult<IoctlResponse> {
    todo!("non-blocking: encode ProgressEvent snapshot")
}
fn handle_pause(_input: &[u8]) -> VckResult<IoctlResponse> {
    todo!("EncryptionEngine::pause")
}
fn handle_jvck_attach(_input: &[u8]) -> VckResult<IoctlResponse> {
    todo!("decode JvckVolumeAttachReq, JvckMetadataStore open/create, attach filter, encode resp")
}
fn handle_detach(_input: &[u8]) -> VckResult<IoctlResponse> {
    todo!("decode VolumeRequest, detach filter, remove from registry")
}
