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
    JvckVolumeAttachReq, JvckVolumeAttachResp, JvckVolumePrepareReq, JvckVolumePrepareResp,
    ProgressEvent, VolumeRequest, VolumeStatus,
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
        IOCTL_JVCK_PREPARE => handle_jvck_prepare(registry, input),
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

/// Shared helper: lock → dismount → re-lock-if-needed → attach filter below FSD
/// → query geometry → unlock.
///
/// Returns `(filter_do, lower_do, sector_size, total_sectors)`.
/// CRITICAL: must be called on an EXPANDED kernel stack (32 KiB) because
/// `IoBuildSynchronousFsdRequest` + `IofCallDriver` in the geometry path
/// consumes significant stack space.
fn do_filter_attach_below_fsd(
    driver: *mut wdk_sys::DRIVER_OBJECT,
    nt_path: &str,
    volume_win32_path: &str,
) -> VckResult<(wdk_sys::PDEVICE_OBJECT, wdk_sys::PDEVICE_OBJECT, u32, u64)> {
    use crate::io::{open_volume_handle_raw, send_fsctl};
    use wdk_sys::ntddk::{
        IoGetRelatedDeviceObject, ObReferenceObjectByHandle, ObfDereferenceObject, ZwClose,
        ZwDeviceIoControlFile,
    };
    use wdk_sys::{PDEVICE_OBJECT as PDO, PFILE_OBJECT};
    const FSCTL_LOCK_VOLUME: u32 = 0x0009_0018;
    const FSCTL_DISMOUNT_VOLUME: u32 = 0x0009_0020;
    const FSCTL_UNLOCK_VOLUME: u32 = 0x0009_001c;
    const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x0007_0000;
    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;

    // Open volume handle (for FSCTLs + geometry + filter attachment target).
    let vol_handle = open_volume_handle_raw(nt_path);
    crate::driver_println!(
        "filter_attach_below_fsd: path={} handle_open={}",
        nt_path, vol_handle.is_some()
    );

    // 1. Optimistic lock.
    let mut held_lock = false;
    if let Some(h) = vol_handle {
        let st = send_fsctl(h, FSCTL_LOCK_VOLUME);
        crate::driver_println!("fsd_below: LOCK(1)=0x{:08x}", st);
        held_lock = crate::nt::nt_success(st);
    }

    // 2. Dismount → FSD releases the stack.
    if let Some(h) = vol_handle {
        let st = send_fsctl(h, FSCTL_DISMOUNT_VOLUME);
        crate::driver_println!("fsd_below: DISMOUNT=0x{:08x}", st);
    }

    // 3. Re-lock if step 1 failed (no race between dismount and attach).
    if !held_lock {
        if let Some(h) = vol_handle {
            let st = send_fsctl(h, FSCTL_LOCK_VOLUME);
            crate::driver_println!("fsd_below: LOCK(2)=0x{:08x}", st);
            held_lock = crate::nt::nt_success(st);
        }
    }
    crate::driver_println!("fsd_below: lock_held={}", held_lock);

    // 4. Obtain target device object from the open file handle (works while locked
    //    and after dismount; IoGetDeviceObjectPointer would need a path open which
    //    fails when no FSD is mounted).
    let target_do: PDO = if let Some(h) = vol_handle {
        let mut fobj: PFILE_OBJECT = null_mut();
        let st = unsafe {
            ObReferenceObjectByHandle(h, 0, null_mut(), 0,
                (&mut fobj as *mut PFILE_OBJECT).cast(), null_mut())
        };
        crate::driver_println!("fsd_below: ObRefByHandle=0x{:08x}", st);
        if crate::nt::nt_success(st) && !fobj.is_null() {
            let do_ptr = unsafe { IoGetRelatedDeviceObject(fobj) };
            unsafe { ObfDereferenceObject(fobj.cast()) };
            do_ptr
        } else { null_mut() }
    } else { null_mut() };
    crate::driver_println!("fsd_below: target_do={:p}", target_do);

    // Query geometry while the lock is held (ZwDeviceIoControlFile works here).
    let (sector_size, total_sectors): (u32, u64) = vol_handle.map_or((512, 0), |h| {
        let mut iosb: wdk_sys::IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        let mut bps = 512u32;
        let mut total = 0u64;
        let mut geom = [0u8; 32];
        if crate::nt::nt_success(unsafe {
            ZwDeviceIoControlFile(h, null_mut(), None, null_mut(), &mut iosb,
                IOCTL_DISK_GET_DRIVE_GEOMETRY, null_mut(), 0, geom.as_mut_ptr().cast(), 32)
        }) {
            bps = u32::from_le_bytes(geom[20..24].try_into().unwrap_or([0;4]));
            if bps == 0 { bps = 512; }
        }
        let mut len_buf = [0u8; 8];
        if crate::nt::nt_success(unsafe {
            ZwDeviceIoControlFile(h, null_mut(), None, null_mut(), &mut iosb,
                IOCTL_DISK_GET_LENGTH_INFO, null_mut(), 0, len_buf.as_mut_ptr().cast(), 8)
        }) {
            total = u64::from_le_bytes(len_buf) / bps as u64;
        }
        crate::driver_println!("fsd_below: geom bps={} total={}", bps, total);
        (bps, total)
    });

    // 5. Attach filter while lock is held → no race re-mount.
    let (fdo, lower_do) = if !target_do.is_null() {
        crate::filter::attach_filter_to_raw_device(driver, target_do)
    } else {
        // Fallback: use Win32 path (may be above NTFS if FSD re-mounted).
        let win32_nt = win32_volume_path_to_nt(volume_win32_path);
        crate::filter::attach_filter_unbound(driver, &win32_nt)
    }.map_err(|err| {
        crate::driver_println!("fsd_below: attach failed: {}", err);
        if held_lock { if let Some(h) = vol_handle { send_fsctl(h, FSCTL_UNLOCK_VOLUME); } }
        if let Some(h) = vol_handle { unsafe { let _ = ZwClose(h); } }
        err
    })?;
    crate::driver_println!("fsd_below: filter_do={:p} lower_do={:p}", fdo, lower_do);

    // 6. Unlock → FSD re-mounts ABOVE our filter.
    if held_lock {
        if let Some(h) = vol_handle {
            let st = send_fsctl(h, FSCTL_UNLOCK_VOLUME);
            crate::driver_println!("fsd_below: UNLOCK=0x{:08x}", st);
        }
    }
    if let Some(h) = vol_handle { unsafe { let _ = ZwClose(h); } }

    Ok((fdo, lower_do, sector_size, total_sectors))
}

/// Dummy `EncryptedOffsetStore` used by provisional (pre-metadata) volumes.
struct DummyOffsetStore {
    total_sectors: u64,
}
impl EncryptedOffsetStore for DummyOffsetStore {
    fn load(&self) -> VckResult<vck_common::types::EncryptedOffset> {
        Ok(vck_common::types::EncryptedOffset { sector: 0, total_sectors: self.total_sectors })
    }
    fn store(&self, _: &vck_common::types::EncryptedOffset) -> VckResult<()> { Ok(()) }
    fn flush(&self) -> VckResult<()> { Ok(()) }
}
/// Dummy `SectorIo` — I/O calls are no-ops; never used before ATTACH completes.
struct DummySectorIo { sector_size: u32, total_sectors: u64 }
impl SectorIo for DummySectorIo {
    fn sector_size(&self) -> u32 { self.sector_size }
    fn total_sectors(&self) -> u64 { self.total_sectors }
    fn read_sectors(&self, _: u64, _: &mut [u8]) -> VckResult<()> {
        Err(VckError::Io("DummySectorIo: not ready yet".into()))
    }
    fn write_sectors(&self, _: u64, _: &[u8]) -> VckResult<()> {
        Err(VckError::Io("DummySectorIo: not ready yet".into()))
    }
}

/// IOCTL_JVCK_PREPARE — Phase 1.
///
/// Attaches the volume filter BELOW the FSD (lock→dismount→attach→unlock) and
/// activates size hiding immediately, so NTFS remounts seeing only the data
/// region. NTFS will NOT write its VBR backup into the footer metadata region.
///
/// After this returns, the app writes JVCK metadata via EnsureJvckMetadata
/// (which uses FSCTL_ALLOW_EXTENDED_DASD_IO to reach the protected tail), then
/// calls IOCTL_JVCK_ATTACH to read the metadata and complete encryption setup.
fn handle_jvck_prepare(registry: &VolumeAttachRegistry, input: &[u8]) -> VckResult<IoctlResponse> {
    crate::driver_println!(
        "jvck_prepare: enter stack={}",
        crate::debug::remaining_stack()
    );
    let req: JvckVolumePrepareReq = decode_req(input)?;
    crate::driver_println!(
        "jvck_prepare: path={} use_h={} use_f={} md_size={}",
        req.volume_path, req.use_header, req.use_footer, req.metadata_size
    );

    if registry.get(&req.volume_path).is_some() {
        return Err(VckError::Unsupported("volume already prepared/attached"));
    }

    let driver = registry.driver_object();
    if driver.is_null() {
        return Err(VckError::Io("driver object not registered".into()));
    }

    let nt_path = if !req.nt_device_path.is_empty() {
        req.nt_device_path.clone()
    } else {
        win32_volume_path_to_nt(&req.volume_path)
    };

    let (filter_do, _lower_do, sector_size, total_sectors) =
        do_filter_attach_below_fsd(driver, &nt_path, &req.volume_path)?;

    if sector_size == 0 || total_sectors == 0 {
        crate::filter::detach_filter(filter_do);
        return Err(VckError::Io("could not query volume geometry".into()));
    }

    // Compute data region geometry from the request (same formula as EnsureJvckMetadata).
    let rs = (req.metadata_size / sector_size) as u64;
    let footer_sectors = req.use_footer as u64 * rs;
    let header_sectors = req.use_header as u64 * rs;
    let data_sectors = total_sectors.saturating_sub(header_sectors + footer_sectors);
    let offset_sector = header_sectors;

    crate::driver_println!(
        "jvck_prepare: data_sectors={} offset_sector={} rs={}",
        data_sectors, offset_sector, rs
    );

    // Create a PROVISIONAL AttachedVolume with correct geometry but no FVEK.
    // The filter uses data_sectors for size-query interception, hiding the footer
    // from NTFS. cipher=None means no crypto and sweep_step is a no-op.
    let volume = Arc::new(AttachedVolume {
        volume_path: req.volume_path.clone(),
        sector_size,
        io_config: IoConfig::AesXts {
            key1: [0u8; 32],
            key2: [0u8; 32],
            offset_sector,
            encrypted_offset: vck_common::types::EncryptedOffset {
                sector: 0,
                total_sectors: data_sectors,
            },
            offset_store: Arc::new(DummyOffsetStore { total_sectors: data_sectors }),
        },
        encryption: Mutex::new(EncryptionEngine::new(
            offset_sector,
            vck_common::types::EncryptedOffset { sector: 0, total_sectors: data_sectors },
        )),
        offset_store: Arc::new(DummyOffsetStore { total_sectors: data_sectors }),
        attach_source: AttachSource::Ioctl,
        filter_device: AtomicPtr::new(filter_do),
        cipher: None, // no FVEK yet
        sweep_io: Mutex::new(Arc::new(DummySectorIo { sector_size, total_sectors: data_sectors })),
        encrypted_boundary: AtomicU64::new(0),
    });
    registry.insert(volume.clone());
    unsafe { crate::filter::filter_bind_volume(filter_do, volume.clone()) };
    crate::driver_println!("jvck_prepare: provisional volume registered, size hiding active");

    encode_resp(&JvckVolumePrepareResp {
        offset_sector,
        data_sectors,
        sector_size,
    })
}

/// IOCTL_JVCK_ATTACH — Phase 2.
///
/// The filter is already in place from IOCTL_JVCK_PREPARE, and the app has
/// written JVCK metadata to the footer (safely, because NTFS can no longer
/// reach the protected region). This IOCTL reads the metadata, derives the
/// FVEK, and replaces the provisional volume with the full AesXts volume.
fn handle_jvck_attach(registry: &VolumeAttachRegistry, input: &[u8]) -> VckResult<IoctlResponse> {
    crate::driver_println!(
        "jvck_attach: enter stack={}",
        crate::debug::remaining_stack()
    );
    let req: JvckVolumeAttachReq = decode_req(input)?;
    crate::driver_println!(
        "jvck_attach: path={} vmk_len={}",
        req.volume_path, req.vmk.len()
    );

    // Find the provisional volume created by PREPARE (has cipher=None).
    let provisional = registry
        .get(&req.volume_path)
        .ok_or(VckError::NotFound("volume not prepared; call IOCTL_JVCK_PREPARE first"))?;

    if provisional.cipher.is_some() {
        return Err(VckError::Unsupported("volume already fully attached"));
    }

    let filter_do = provisional.filter_device.load(Ordering::Acquire);
    let sector_size = provisional.sector_size;
    let data_sectors = provisional.data_sectors();

    // NT path for I/O: use nt_device_path if provided, else derive from volume_path.
    let io_nt_path = if !req.nt_device_path.is_empty() {
        req.nt_device_path.clone()
    } else {
        win32_volume_path_to_nt(&req.volume_path)
    };
    let io_volume_id = VolumeId {
        partition_guid: Guid::nil(),
        device_path: io_nt_path.clone(),
    };

    // Now NTFS is mounted above our filter and sees only the data region (reduced
    // size). Sector `partition_total - 1` is outside NTFS's visible range so NTFS
    // never placed its VBR backup or cache there. ZwReadFile with
    // FILE_NO_INTERMEDIATE_BUFFERING goes directly to the raw device, bypassing
    // any NTFS page cache.
    let _ = (sector_size, data_sectors); // used via provisional only for context logging
    let probe_io = KernelVolumeIo::open_query(&io_volume_id).map_err(|err| {
        crate::driver_println!("jvck_attach: probe open_query failed: {}", err);
        err
    })?;
    let partition_total = probe_io.total_sectors();
    crate::driver_println!(
        "jvck_attach: partition_total={} sector_size={}",
        partition_total, probe_io.sector_size()
    );

    // Diagnostic: print footer bytes.
    {
        let footer_lba = partition_total.saturating_sub(1);
        let mut diag = alloc::vec![0u8; probe_io.sector_size() as usize];
        if probe_io.read_sectors(footer_lba, &mut diag).is_ok() {
            crate::driver_println!(
                "jvck_attach: footer_lba={} bytes=[{:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x}]",
                footer_lba,
                diag[0], diag[1], diag[2], diag[3],
                diag[4], diag[5], diag[6], diag[7]
            );
        }
    }

    let store = JvckMetadataStore::open(probe_io, &req.vmk).map_err(|err| {
        crate::driver_println!("jvck_attach: metadata open failed: {}", err);
        err
    })?;
    crate::driver_println!("jvck_attach: metadata opened");

    let offset_sector = store.offset_sector();
    let store_data_sectors = store.data_sector_count();
    let store_sector_size = store.sector_size();
    let encrypted_offset = EncryptedOffset {
        sector: store.load_offset()?,
        total_sectors: store_data_sectors,
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
    let sweep_io: Arc<dyn SectorIo> = Arc::new(
        KernelVolumeIo::open(&io_volume_id, store_sector_size, store_data_sectors)?
    );

    // Replace the provisional volume with the complete one. The filter_do stays;
    // we just swap the volume bound to its extension.
    registry.remove(&req.volume_path);

    let initial_boundary = encrypted_offset.sector;
    let volume = Arc::new(AttachedVolume {
        volume_path: req.volume_path.clone(),
        sector_size: store_sector_size,
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
    unsafe { crate::filter::filter_rebind_volume(filter_do, volume.clone()) };
    crate::driver_println!("jvck_attach: volume complete and rebound, done");

    encode_resp(&JvckVolumeAttachResp {
        offset_sector,
        total_sectors: store_data_sectors,
        sector_size: store_sector_size,
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
