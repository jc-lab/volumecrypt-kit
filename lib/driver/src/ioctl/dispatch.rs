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

    // Win32 path for filter attach (IoGetDeviceObjectPointer uses this).
    let volume_id = VolumeId {
        partition_guid: Guid::nil(),
        device_path: win32_volume_path_to_nt(&req.volume_path),
    };
    // NT device path for ZwCreateFile. When the app supplies
    // `nt_device_path` (e.g. `\Device\HarddiskVolume3`), we prefer it because
    // it works even when the filesystem is transiently dismounted.
    let io_nt_path = if !req.nt_device_path.is_empty() {
        req.nt_device_path.clone()
    } else {
        volume_id.device_path.clone()
    };
    crate::driver_println!(
        "jvck_attach: begin attach_path={} io_path={} stack={}",
        volume_id.device_path,
        io_nt_path,
        crate::debug::remaining_stack()
    );

    let io_volume_id = VolumeId {
        partition_guid: Guid::nil(),
        device_path: io_nt_path.clone(),
    };

    let driver = registry.driver_object();
    if driver.is_null() {
        return Err(VckError::Io("driver object not registered".into()));
    }

    // Sequence: open volume handle → attach filter (IoGetDeviceObjectPointer) →
    // lock → dismount → unlock.  This inserts the filter BELOW the FSD so NTFS
    // re-mounts above it on unlock.
    let filter_do = {
        use crate::io::{open_volume_handle_raw, send_fsctl};
        use wdk_sys::ntddk::ZwClose;
        const FSCTL_LOCK_VOLUME: u32 = 0x0009_0018;
        const FSCTL_DISMOUNT_VOLUME: u32 = 0x0009_0020;
        const FSCTL_UNLOCK_VOLUME: u32 = 0x0009_001c;

        // Open a handle for lock/dismount/unlock before attaching the filter.
        let vol_handle = open_volume_handle_raw(&io_nt_path);
        crate::driver_println!("jvck_attach: vol_handle_open={}", vol_handle.is_some());

        // Attach the filter while the volume is still mounted (IoGetDeviceObjectPointer needs a mounted path).
        let (fdo, _ldo) =
            crate::filter::attach_filter_unbound(driver, &volume_id.device_path)
                .map_err(|err| {
                    crate::driver_println!("jvck_attach: attach_filter_unbound failed: {}", err);
                    if let Some(h) = vol_handle { unsafe { let _ = ZwClose(h); } }
                    err
                })?;
        crate::driver_println!("jvck_attach: filter attached");

        if let Some(h) = vol_handle {
            let lock_st = send_fsctl(h, FSCTL_LOCK_VOLUME);
            crate::driver_println!("jvck_attach: LOCK_VOLUME=0x{:08x}", lock_st);
            if crate::nt::nt_success(lock_st) {
                let dis_st = send_fsctl(h, FSCTL_DISMOUNT_VOLUME);
                crate::driver_println!("jvck_attach: DISMOUNT_VOLUME=0x{:08x}", dis_st);
            }
            let unlock_st = send_fsctl(h, FSCTL_UNLOCK_VOLUME);
            crate::driver_println!("jvck_attach: UNLOCK_VOLUME=0x{:08x}", unlock_st);
            unsafe { let _ = ZwClose(h); }
        }
        fdo
    };

    // Open metadata via the NT device path — works regardless of mount state.
    let probe_io = KernelVolumeIo::open_query(&io_volume_id).map_err(|err| {
        crate::driver_println!("jvck_attach: probe open failed: {}, detaching filter", err);
        crate::filter::detach_filter(filter_do);
        err
    })?;
    crate::driver_println!("jvck_attach: open_query ok");
    let store = JvckMetadataStore::open(probe_io, &req.vmk).map_err(|err| {
        crate::driver_println!("jvck_attach: open failed: {}, detaching filter", err);
        crate::filter::detach_filter(filter_do);
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

    crate::driver_println!("jvck_attach: build cipher + sweep_io");
    let cipher = AesXtsCipher::new(key1, key2)?;
    let sweep_io: Arc<dyn SectorIo> = Arc::new(KernelVolumeIo::open_query(&io_volume_id).map_err(|err| {
        crate::filter::detach_filter(filter_do);
        err
    })?);

    let initial_boundary = encrypted_offset.sector;
    let volume = Arc::new(AttachedVolume {
        volume_path: req.volume_path.clone(),
        sector_size,
        io_config,
        encryption: Mutex::new(EncryptionEngine::new(offset_sector, encrypted_offset)),
        offset_store,
        attach_source: AttachSource::Ioctl,
        filter_device: AtomicPtr::new(filter_do),
        cipher: Some(cipher),
        sweep_io: Mutex::new(sweep_io),
        encrypted_boundary: AtomicU64::new(initial_boundary),
    });
    registry.insert(volume.clone());
    unsafe { crate::filter::filter_bind_volume(filter_do, volume.clone()) };
    crate::driver_println!("jvck_attach: volume registered and filter bound, done");

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
