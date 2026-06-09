//! IRP_MJ_DEVICE_CONTROL handler. Authorizes, then routes by IOCTL code.
//!
//! GET_PROGRESS is non-blocking: it returns the current snapshot immediately.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use spin::Mutex;
use vck_common::{
    jvck::JvckMetadataStore, types::Guid, EncryptedOffset, EncryptedOffsetStore, SectorIo,
    VckError, VckResult, VolumeId,
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
    crate::driver_println!(
        "dispatch: ioctl=0x{:08x} authorized, input_len={} stack={}",
        ctx.ioctl_code,
        input.len(),
        crate::debug::remaining_stack()
    );
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
    crate::driver_println!(
        "jvck_attach: enter, decoding request stack={}",
        crate::debug::remaining_stack()
    );
    let req: JvckVolumeAttachReq = decode_req(input)?;
    crate::driver_println!(
        "jvck_attach: decoded path={} vmk_len={} use_h={} use_f={} md_size={}",
        req.volume_path,
        req.vmk.len(),
        req.use_header,
        req.use_footer,
        req.metadata_size
    );

    if registry.get(&req.volume_path).is_some() {
        return Err(VckError::Unsupported("volume already attached"));
    }

    let volume_id = VolumeId {
        partition_guid: Guid::nil(),
        device_path: win32_volume_path_to_nt(&req.volume_path),
    };
    crate::driver_println!(
        "jvck_attach: begin nt_path={} stack={}",
        volume_id.device_path,
        crate::debug::remaining_stack()
    );

    // Open EXISTING JVCK metadata. First-time creation (FVEK generation + footer
    // write over an extended-DASD handle) is done by the user-space SDK before
    // attach, so a volume with no metadata is an error here rather than an
    // implicit create.
    let probe_io = KernelVolumeIo::open_query(&volume_id)?;
    crate::driver_println!("jvck_attach: open_query ok");
    let store = JvckMetadataStore::open(probe_io, &req.vmk).map_err(|err| {
        crate::driver_println!("jvck_attach: open failed: {}", err);
        err
    })?;
    crate::driver_println!("jvck_attach: existing metadata opened");

    let offset_sector = store.offset_sector();
    let data_sectors = store.data_sector_count();
    let sector_size = store.sector_size();
    let encrypted_offset = EncryptedOffset {
        sector: store.load_offset()?,
        total_sectors: data_sectors,
    };
    let (key1, key2) = store.fvek_keys();
    let (key1, key2) = (*key1, *key2);

    let offset_store: Arc<dyn EncryptedOffsetStore> = Arc::new(store);
    let io_config = IoConfig::AesXts {
        key1,
        key2,
        offset_sector,
        encrypted_offset: encrypted_offset.clone(),
        offset_store: offset_store.clone(),
    };

    crate::driver_println!("jvck_attach: build cipher");
    let cipher = AesXtsCipher::new(key1, key2)?;
    // Placeholder sweep_io (same volume path, replaced below with lower-device handle).
    let placeholder_io: Arc<dyn SectorIo> = Arc::new(KernelVolumeIo::open_query(&volume_id)?);

    let initial_boundary = encrypted_offset.sector;
    let volume = Arc::new(AttachedVolume {
        volume_path: req.volume_path.clone(),
        sector_size,
        io_config,
        encryption: Mutex::new(EncryptionEngine::new(offset_sector, encrypted_offset)),
        offset_store,
        attach_source: AttachSource::Ioctl,
        filter_device: AtomicPtr::new(null_mut()),
        cipher: Some(cipher),
        sweep_io: Mutex::new(placeholder_io),
        encrypted_boundary: AtomicU64::new(initial_boundary),
    });
    registry.insert(volume.clone());
    crate::driver_println!("jvck_attach: registered, attaching filter");

    // Attach a transparent filter above the volume so live filesystem I/O can
    // be encrypted/decrypted in flight.
    let driver = registry.driver_object();
    if driver.is_null() {
        registry.remove(&req.volume_path);
        return Err(VckError::Io("driver object not registered".into()));
    }
    let lower_do = match crate::filter::attach_filter(driver, &volume_id.device_path, volume.clone()) {
        Ok((filter_do, lower_do)) => {
            volume.filter_device.store(filter_do, Ordering::Release);
            lower_do
        }
        Err(err) => {
            registry.remove(&req.volume_path);
            return Err(err);
        }
    };

    // NOTE: sweep_io bypass of the filter is a TODO. The encrypted boundary is
    // tracked via AtomicU64 so the filter completion routines never acquire
    // encryption.lock() — avoiding the deadlock even when sweep_io I/O passes
    // through the filter. The remaining issue (raw NTFS write acceptance) is
    // deferred to a dedicated sweep I/O path task.
    let _ = lower_do; // suppress unused warning until the bypass is wired up
    crate::driver_println!("jvck_attach: filter attached, done");

    encode_resp(&JvckVolumeAttachResp {
        offset_sector,
        total_sectors: data_sectors,
        sector_size,
    })
}

fn handle_detach(registry: &VolumeAttachRegistry, input: &[u8]) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    let volume = registry
        .remove(&req.volume_path)
        .ok_or(VckError::NotFound("volume is not attached"))?;

    let filter_do = volume.filter_device.swap(null_mut(), Ordering::AcqRel);
    if !filter_do.is_null() {
        crate::filter::detach_filter(filter_do);
    }
    encode_resp(&EmptyResponse {})
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
