//! IRP_MJ_DEVICE_CONTROL handler. Authorizes, then routes by IOCTL code.
//!
//! GET_PROGRESS is non-blocking: it returns the current snapshot immediately.

use alloc::string::{String, ToString};
use alloc::sync::Arc;

use spin::Mutex;
use vck_common::{
    jvck::{JvckMetadataStore, JvckMetadataOptions},
    types::Guid,
    EncryptedOffset, EncryptedOffsetStore, SectorIo, VckError, VckResult, VolumeId,
};

use crate::{
    crypto::aes_xts::AesXtsCipher,
    io::KernelVolumeIo,
    ioctl::codes::*,
    nt::win32_volume_path_to_nt,
    offset::engine::EncryptionEngine,
    provider::{IoConfig, IoctlAuthContext, IoctlAuthorization},
    registry::{AttachSource, AttachedVolume, VolumeAttachRegistry},
};

/// Serialized msgpack response buffer to copy back to the caller.
use alloc::vec::Vec;
use serde::Serialize;

use super::types::{
    JvckVolumeAttachReq, JvckVolumeAttachResp, ProgressEvent, VolumeRequest, VolumeStatus,
};
pub type IoctlResponse = Vec<u8>;

/// Authorize then dispatch. `auth` is the sample-provided policy; `input` is the
/// caller's msgpack request buffer.
pub fn dispatch_ioctl<A: IoctlAuthorization>(
    auth: &A,
    registry: &VolumeAttachRegistry,
    ctx: &IoctlAuthContext<'_>,
    input: &[u8],
) -> VckResult<IoctlResponse> {
    auth.authorize(ctx)?;
    match ctx.ioctl_code {
        IOCTL_VCK_GET_STATUS => handle_get_status(registry, input),
        IOCTL_VCK_START_ENCRYPT => handle_start_encrypt(registry, input),
        IOCTL_VCK_START_DECRYPT => handle_start_decrypt(registry, input),
        IOCTL_VCK_GET_PROGRESS => handle_get_progress(registry, input),
        IOCTL_VCK_PAUSE => handle_pause(registry, input),
        IOCTL_JVCK_ATTACH => handle_jvck_attach(registry, input),
        IOCTL_VCK_DETACH => handle_detach(registry, input),
        _ => Err(VckError::Unsupported("unknown IOCTL code")),
    }
}

#[derive(Serialize)]
struct EmptyResponse {}

fn handle_get_status(registry: &VolumeAttachRegistry, input: &[u8]) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    if let Some(volume) = registry.get(&req.volume_path) {
        let snapshot = volume.encryption.lock().snapshot();
        encode_resp(&VolumeStatus {
            volume_path: volume.volume_path.clone(),
            state: snapshot.state.as_wire(),
            encrypted_sector: snapshot.encrypted_sector,
            total_sectors: snapshot.total_sectors,
            sector_size: volume.sector_size,
            is_attached: true,
        })
    } else {
        encode_resp(&VolumeStatus {
            volume_path: req.volume_path,
            state: 0,
            encrypted_sector: 0,
            total_sectors: 0,
            sector_size: 0,
            is_attached: false,
        })
    }
}

fn handle_start_encrypt(
    registry: &VolumeAttachRegistry,
    input: &[u8],
) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    let volume = registry
        .get(&req.volume_path)
        .ok_or(VckError::NotFound("volume is not attached"))?;
    volume.encryption.lock().start_encrypt();
    encode_resp(&EmptyResponse {})
}

fn handle_start_decrypt(
    registry: &VolumeAttachRegistry,
    input: &[u8],
) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    let volume = registry
        .get(&req.volume_path)
        .ok_or(VckError::NotFound("volume is not attached"))?;
    volume.encryption.lock().start_decrypt();
    encode_resp(&EmptyResponse {})
}

fn handle_get_progress(
    registry: &VolumeAttachRegistry,
    input: &[u8],
) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    let volume = registry
        .get(&req.volume_path)
        .ok_or(VckError::NotFound("volume is not attached"))?;
    let snapshot = volume.encryption.lock().snapshot();
    encode_resp(&ProgressEvent {
        encrypted_sector: snapshot.encrypted_sector,
        total_sectors: snapshot.total_sectors,
        state: snapshot.state.as_wire(),
        error: String::new(),
    })
}

fn handle_pause(registry: &VolumeAttachRegistry, input: &[u8]) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    let volume = registry
        .get(&req.volume_path)
        .ok_or(VckError::NotFound("volume is not attached"))?;
    volume.encryption.lock().pause();
    encode_resp(&EmptyResponse {})
}

fn handle_jvck_attach(registry: &VolumeAttachRegistry, input: &[u8]) -> VckResult<IoctlResponse> {
    let req: JvckVolumeAttachReq = decode_req(input)?;

    if registry.get(&req.volume_path).is_some() {
        return Err(VckError::Unsupported("volume already attached"));
    }

    let volume_id = VolumeId {
        partition_guid: Guid::nil(),
        device_path: win32_volume_path_to_nt(&req.volume_path),
    };

    // Open existing JVCK metadata, or create it on first-time encryption using
    // the app-provided FVEK / volume id. `open`/`create` each consume a fresh
    // KernelVolumeIo (the failed `open` drops its handle).
    let store = match JvckMetadataStore::open(KernelVolumeIo::open_query(&volume_id)?, &req.vmk) {
        Ok(store) => store,
        Err(VckError::NotFound(_)) => {
            let options = JvckMetadataOptions {
                use_header: req.use_header,
                use_footer: req.use_footer,
                metadata_size: req.metadata_size,
            };
            JvckMetadataStore::create(
                KernelVolumeIo::open_query(&volume_id)?,
                &req.vmk,
                options,
                to_key(&req.fvek_key1, "fvek_key1")?,
                to_key(&req.fvek_key2, "fvek_key2")?,
                to_volume_id(&req.volume_id)?,
            )?
        }
        Err(err) => return Err(err),
    };

    let meta = store.load_metadata()?;
    let offset_sector = store.offset_sector();
    let data_sectors = store.data_sector_count();
    let sector_size = store.sector_size();
    let encrypted_offset = EncryptedOffset {
        sector: meta.encrypted_offset,
        total_sectors: data_sectors,
    };

    let offset_store: Arc<dyn EncryptedOffsetStore> = Arc::new(store);
    let io_config = IoConfig::AesXts {
        key1: meta.fvek_key1,
        key2: meta.fvek_key2,
        offset_sector,
        encrypted_offset: encrypted_offset.clone(),
        offset_store: offset_store.clone(),
    };

    // Cipher + raw volume I/O for the background sweep. (No filter yet, so the
    // sweep addresses the volume device directly.)
    let cipher = AesXtsCipher::new(meta.fvek_key1, meta.fvek_key2)?;
    let sweep_io: Arc<dyn SectorIo> = Arc::new(KernelVolumeIo::open_query(&volume_id)?);

    registry.insert(Arc::new(AttachedVolume {
        volume_path: req.volume_path.clone(),
        sector_size,
        io_config,
        encryption: Mutex::new(EncryptionEngine::new(offset_sector, encrypted_offset)),
        offset_store,
        attach_source: AttachSource::Ioctl,
        cipher: Some(cipher),
        sweep_io,
    }));

    encode_resp(&JvckVolumeAttachResp {
        offset_sector,
        total_sectors: data_sectors,
        sector_size,
    })
}

fn handle_detach(registry: &VolumeAttachRegistry, input: &[u8]) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    registry
        .remove(&req.volume_path)
        .ok_or(VckError::NotFound("volume is not attached"))?;
    // TODO(driver): detach the volume filter device once filter attach is wired.
    encode_resp(&EmptyResponse {})
}

fn to_key(bytes: &[u8], what: &'static str) -> VckResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| VckError::InvalidData(what))
}

fn to_volume_id(bytes: &[u8]) -> VckResult<[u8; 16]> {
    bytes
        .try_into()
        .map_err(|_| VckError::InvalidData("volume_id must be 16 bytes"))
}

fn decode_req<T>(input: &[u8]) -> VckResult<T>
where
    T: serde::de::DeserializeOwned,
{
    messagepack_serde::from_slice(input).map_err(|err| VckError::MsgpackDecode(err.to_string()))
}

fn encode_resp<T>(value: &T) -> VckResult<IoctlResponse>
where
    T: Serialize,
{
    messagepack_serde::to_vec(value).map_err(|err| VckError::MsgpackEncode(err.to_string()))
}
