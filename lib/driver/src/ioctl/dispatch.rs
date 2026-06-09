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
    io::{KernelVolumeIo, LowerDeviceIo, OffsetSectorIo},
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
    let nt_path = win32_volume_path_to_nt(&req.volume_path);

    // Check if our filter is correctly placed BELOW the FSD (AddDevice path).
    // This is true when find_our_filter_in_stack succeeds: means NTFS VCB is
    // above our filter in the device stack.
    let filter_below_fsd = crate::filter::find_our_filter_in_stack(&nt_path).is_some();

    if let Some(volume) = registry.get(&req.volume_path) {
        let snapshot = volume.encryption.lock().snapshot();
        encode_resp(&VolumeStatus {
            volume_path: volume.volume_path.clone(),
            state: snapshot.state.as_wire(),
            encrypted_sector: snapshot.encrypted_sector,
            total_sectors: snapshot.total_sectors,
            sector_size: volume.sector_size,
            is_attached: true,
            filter_below_fsd,
        })
    } else {
        encode_resp(&VolumeStatus {
            volume_path: req.volume_path,
            state: 0,
            encrypted_sector: 0,
            total_sectors: 0,
            sector_size: 0,
            is_attached: false,
            filter_below_fsd,
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

// FSCTL codes used in PREPARE.
const FSCTL_LOCK_VOLUME: u32 = 0x0009_0018;
const FSCTL_DISMOUNT_VOLUME: u32 = 0x0009_0020;
const FSCTL_UNLOCK_VOLUME: u32 = 0x0009_001c;
const IOCTL_DISK_GET_DRIVE_GEOMETRY_PREPARE: u32 = 0x0007_0000;
const IOCTL_DISK_GET_LENGTH_INFO_PREPARE: u32 = 0x0007_405C;

/// PREPARE via the AddDevice path: filter is already below NTFS, use LowerDeviceIo
/// for all I/O so we bypass NTFS write protection and PartMgr sector-0 guards.
fn handle_jvck_prepare_adddevice_path(
    registry: &VolumeAttachRegistry,
    req: JvckVolumePrepareReq,
    nt_path: String,
    driver: *mut wdk_sys::DRIVER_OBJECT,
    filter_do: wdk_sys::PDEVICE_OBJECT,
    lower_do: wdk_sys::PDEVICE_OBJECT,
) -> VckResult<IoctlResponse> {
    use vck_common::jvck::metadata::{self, METADATA_BLOCK_SIZE};
    use crate::crypto::aes_xts::AesXtsCipher;
    use wdk_sys::ntddk::ZwDeviceIoControlFile;

    // Query geometry (NTFS is mounted, ZwCreateFile works via existing filter pass-through).
    let io_volume_id = VolumeId { partition_guid: Guid::nil(), device_path: nt_path.clone() };
    let geom_io = KernelVolumeIo::open_query(&io_volume_id).map_err(|e| {
        crate::driver_println!("jvck_prepare(add): geom open failed: {}", e);
        e
    })?;
    let sector_size = geom_io.sector_size();
    let total_sectors = geom_io.total_sectors();
    crate::driver_println!("jvck_prepare(add): bps={} total={}", sector_size, total_sectors);
    drop(geom_io);

    // Compute replica geometry.
    let rs = (req.metadata_size / sector_size) as u64;
    let footer_sectors = req.use_footer as u64 * rs;
    let header_sectors = req.use_header as u64 * rs;
    let data_sectors = total_sectors.saturating_sub(header_sectors + footer_sectors);
    let offset_sector = header_sectors;

    // LowerDeviceIo targets the raw device below our filter.
    // This bypasses NTFS, HarddiskVolume5, AND PartMgr (since we're below them all).
    let lo = LowerDeviceIo::new(lower_do, sector_size, total_sectors);

    // Write metadata replicas via LowerDeviceIo.
    if !req.metadata_block.is_empty() {
        if req.metadata_block.len() < METADATA_BLOCK_SIZE {
            return Err(VckError::InvalidData("metadata_block too short"));
        }
        let replica_lbas = {
            let mut v: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
            for i in 0..req.use_header as u64 { v.push(i * rs); }
            let fs = total_sectors - (req.use_footer as u64 * rs);
            for j in 0..req.use_footer as u64 { v.push(fs + j * rs + rs - 1); }
            v
        };
        let mut sector_buf = alloc::vec![0u8; sector_size as usize];
        let copy_len = METADATA_BLOCK_SIZE.min(sector_size as usize);
        sector_buf[..copy_len].copy_from_slice(&req.metadata_block[..copy_len]);
        for lba in &replica_lbas {
            lo.write_sectors(*lba, &sector_buf).map_err(|e| {
                crate::driver_println!("jvck_prepare(add): metadata write lba={} err: {}", lba, e);
                e
            })?;
            crate::driver_println!("jvck_prepare(add): wrote metadata lba={}", lba);
        }
    }

    // Encrypt sector 0 via LowerDeviceIo — bypasses PartMgr protection!
    if !req.metadata_block.is_empty() && !req.vmk.is_empty() {
        match metadata::decrypt_payload(&req.metadata_block[..METADATA_BLOCK_SIZE.min(req.metadata_block.len())], &req.vmk) {
            Ok((_off, secrets)) => {
                if let Ok(cipher) = AesXtsCipher::new(secrets.fvek_key1, secrets.fvek_key2) {
                    let mut s0 = alloc::vec![0u8; sector_size as usize];
                    if lo.read_sectors(0, &mut s0).is_ok() {
                        cipher.encrypt_sector(0, &mut s0);
                        match lo.write_sectors(0, &s0) {
                            Ok(()) => crate::driver_println!("jvck_prepare(add): sector 0 encrypted"),
                            Err(e) => crate::driver_println!("jvck_prepare(add): sector 0 write err: {}", e),
                        }
                    }
                }
            }
            Err(e) => crate::driver_println!("jvck_prepare(add): decrypt_payload err: {}", e),
        }
    }

    // Bind provisional volume (size hiding active).
    let volume = Arc::new(AttachedVolume {
        volume_path: req.volume_path.clone(),
        sector_size,
        io_config: IoConfig::AesXts {
            key1: [0u8; 32], key2: [0u8; 32],
            offset_sector,
            encrypted_offset: vck_common::types::EncryptedOffset { sector: 0, total_sectors: data_sectors },
            offset_store: Arc::new(DummyOffsetStore { total_sectors: data_sectors }),
        },
        encryption: Mutex::new(EncryptionEngine::new(
            offset_sector,
            vck_common::types::EncryptedOffset { sector: 0, total_sectors: data_sectors },
        )),
        offset_store: Arc::new(DummyOffsetStore { total_sectors: data_sectors }),
        attach_source: AttachSource::Ioctl,
        filter_device: AtomicPtr::new(filter_do),
        cipher: None,
        sweep_io: Mutex::new(Arc::new(DummySectorIo { sector_size, total_sectors: data_sectors })),
        encrypted_boundary: AtomicU64::new(0),
    });
    registry.insert(volume.clone());
    unsafe { crate::filter::filter_bind_volume(filter_do, volume.clone()) };
    crate::driver_println!("jvck_prepare(add): provisional volume bound (AddDevice path)");

    // Query storage device info for sweep_io path.
    const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;
    const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048;
    let (raw_partition_path, raw_disk_path, partition_start_lba) = 'paths: {
        use crate::io::open_volume_handle_raw;
        use wdk_sys::ntddk::ZwClose;
        let mut sdn = [0u32; 3];
        let mut partition_info = [0u8; 64];
        if let Some(h) = open_volume_handle_raw(&nt_path) {
            let mut iosb: wdk_sys::IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
            unsafe {
                ZwDeviceIoControlFile(h, null_mut(), None, null_mut(), &mut iosb,
                    IOCTL_STORAGE_GET_DEVICE_NUMBER, null_mut(), 0, sdn.as_mut_ptr().cast(), 12);
                ZwDeviceIoControlFile(h, null_mut(), None, null_mut(), &mut iosb,
                    IOCTL_DISK_GET_PARTITION_INFO_EX, null_mut(), 0, partition_info.as_mut_ptr().cast(), 64);
                let _ = ZwClose(h);
            }
        }
        let disk_num = sdn[1];
        let part_num = sdn[2];
        let start_bytes = u64::from_le_bytes(partition_info[4..12].try_into().unwrap_or([0;8]));
        let start_lba = start_bytes / sector_size as u64;
        break 'paths (
            alloc::format!(r"\Device\Harddisk{}\Partition{}", disk_num, part_num),
            alloc::format!(r"\Device\Harddisk{}\DR0", disk_num),
            start_lba,
        );
    };

    // If VMK provided, complete full attach (read metadata → cipher → sweep).
    if !req.vmk.is_empty() && !req.metadata_block.is_empty() {
        let probe_io = KernelVolumeIo::open_query(&io_volume_id).map_err(|e| {
            registry.remove(&req.volume_path);
            crate::filter::detach_filter(filter_do);
            e
        })?;
        let store = JvckMetadataStore::open(probe_io, &req.vmk).map_err(|e| {
            registry.remove(&req.volume_path);
            crate::filter::detach_filter(filter_do);
            e
        })?;
        let store_offset = store.offset_sector();
        let store_data = store.data_sector_count();
        let store_bps = store.sector_size();
        let encrypted_offset = EncryptedOffset {
            sector: store.load_offset()?,
            total_sectors: store_data,
        };
        let (key1, key2) = store.fvek_keys();
        let (key1, key2) = (*key1, *key2);
        let offset_store: Arc<dyn EncryptedOffsetStore> = Arc::new(store);
        let io_config = IoConfig::AesXts {
            key1, key2, offset_sector: store_offset,
            encrypted_offset: encrypted_offset.clone(),
            offset_store: offset_store.clone(),
        };
        let cipher = AesXtsCipher::new(key1, key2)?;
        // sweep_io uses LowerDeviceIo — direct to raw disk, below PartMgr ✓
        let sweep_io: Arc<dyn SectorIo> = Arc::new(
            LowerDeviceIo::new(lower_do, store_bps, store_data)
        );
        registry.remove(&req.volume_path);
        let boundary = encrypted_offset.sector;
        let complete = Arc::new(AttachedVolume {
            volume_path: req.volume_path.clone(),
            sector_size: store_bps,
            io_config,
            encryption: Mutex::new(EncryptionEngine::new(store_offset, encrypted_offset)),
            offset_store,
            attach_source: AttachSource::Ioctl,
            filter_device: AtomicPtr::new(filter_do),
            cipher: Some(cipher),
            sweep_io: Mutex::new(sweep_io),
            encrypted_boundary: AtomicU64::new(boundary),
        });
        registry.insert(complete.clone());
        unsafe { crate::filter::filter_rebind_volume(filter_do, complete) };
        crate::driver_println!("jvck_prepare(add): fully attached offset={} data={}", store_offset, store_data);
        return encode_resp(&JvckVolumePrepareResp {
            offset_sector: store_offset, data_sectors: store_data, sector_size: store_bps,
            raw_partition_path, raw_disk_path, partition_start_lba, fully_attached: true,
        });
    }

    encode_resp(&JvckVolumePrepareResp {
        offset_sector, data_sectors, sector_size,
        raw_partition_path, raw_disk_path, partition_start_lba, fully_attached: false,
    })
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

/// IOCTL_JVCK_PREPARE — Unified attach + metadata write.
///
/// Two paths depending on whether AddDevice (reboot-based) pre-attached the filter:
///
/// **AddDevice path** (preferred, after driver install + reboot):
///   The filter is already below NTFS. We find it via device stack walk, obtain
///   `lower_do` (raw partition/disk device below PartMgr), use `LowerDeviceIo`
///   for ALL I/O: metadata write + sector-0 encryption + sweep. No lock/dismount.
///
/// **Fallback path** (first install, no reboot yet):
///   lock → dismount → re-lock → attach filter → write metadata → unlock.
///   Same as before, with PartMgr protection for sector 0 bypassed by dismount.
fn handle_jvck_prepare(registry: &VolumeAttachRegistry, input: &[u8]) -> VckResult<IoctlResponse> {
    use crate::io::{open_volume_handle_raw, send_fsctl};
    use wdk_sys::ntddk::{
        IoGetRelatedDeviceObject, ObReferenceObjectByHandle, ObfDereferenceObject, ZwClose,
        ZwDeviceIoControlFile,
    };
    use wdk_sys::{PDEVICE_OBJECT as PDO, PFILE_OBJECT};

    crate::driver_println!(
        "jvck_prepare: enter stack={}",
        crate::debug::remaining_stack()
    );
    let req: JvckVolumePrepareReq = decode_req(input)?;
    crate::driver_println!(
        "jvck_prepare: path={} use_h={} use_f={} md_size={} block_len={}",
        req.volume_path, req.use_header, req.use_footer, req.metadata_size,
        req.metadata_block.len()
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

    // ── Try AddDevice path first ───────────────────────────────────────────
    // After driver install + reboot, AddDevice has attached an unbound filter
    // below NTFS. Find it by walking the device stack.
    if let Some((filter_do, lower_do)) = crate::filter::find_our_filter_in_stack(&nt_path) {
        crate::driver_println!(
            "jvck_prepare: AddDevice filter found filter={:p} lower={:p}",
            filter_do, lower_do
        );
        return handle_jvck_prepare_adddevice_path(
            registry, req, nt_path, driver, filter_do, lower_do,
        );
    }
    crate::driver_println!("jvck_prepare: no pre-attached filter, using lock/dismount fallback");

    // Open vol_handle early — used for FSCTLs, geometry, metadata write.
    let vol_handle = open_volume_handle_raw(&nt_path);
    crate::driver_println!("jvck_prepare: vol_handle_open={}", vol_handle.is_some());

    // ── Step 1: lock → dismount → re-lock ──────────────────────────────────
    let mut held_lock = false;
    if let Some(h) = vol_handle {
        let st = send_fsctl(h, FSCTL_LOCK_VOLUME);
        crate::driver_println!("jvck_prepare: LOCK(1)=0x{:08x}", st);
        held_lock = crate::nt::nt_success(st);
    }
    if let Some(h) = vol_handle {
        let st = send_fsctl(h, FSCTL_DISMOUNT_VOLUME);
        crate::driver_println!("jvck_prepare: DISMOUNT=0x{:08x}", st);
    }
    if !held_lock {
        if let Some(h) = vol_handle {
            let st = send_fsctl(h, FSCTL_LOCK_VOLUME);
            crate::driver_println!("jvck_prepare: LOCK(2)=0x{:08x}", st);
            held_lock = crate::nt::nt_success(st);
        }
    }
    crate::driver_println!("jvck_prepare: lock_held={}", held_lock);

    // Query geometry while locked.
    let (sector_size, total_sectors): (u32, u64) = vol_handle.map_or((512, 0), |h| {
        let mut iosb: wdk_sys::IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        let mut bps = 512u32;
        let mut total = 0u64;
        let mut geom = [0u8; 32];
        if crate::nt::nt_success(unsafe {
            ZwDeviceIoControlFile(h, null_mut(), None, null_mut(), &mut iosb,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_PREPARE, null_mut(), 0,
                geom.as_mut_ptr().cast(), 32)
        }) {
            bps = u32::from_le_bytes(geom[20..24].try_into().unwrap_or([0;4]));
            if bps == 0 { bps = 512; }
        }
        let mut len_buf = [0u8; 8];
        if crate::nt::nt_success(unsafe {
            ZwDeviceIoControlFile(h, null_mut(), None, null_mut(), &mut iosb,
                IOCTL_DISK_GET_LENGTH_INFO_PREPARE, null_mut(), 0,
                len_buf.as_mut_ptr().cast(), 8)
        }) {
            total = u64::from_le_bytes(len_buf) / bps as u64;
        }
        crate::driver_println!("jvck_prepare: geom bps={} total={}", bps, total);
        (bps, total)
    });

    if sector_size == 0 || total_sectors == 0 {
        if held_lock { if let Some(h) = vol_handle { send_fsctl(h, FSCTL_UNLOCK_VOLUME); } }
        if let Some(h) = vol_handle { unsafe { let _ = ZwClose(h); } }
        return Err(VckError::Io("could not query volume geometry".into()));
    }

    // Compute replica geometry.
    let rs = (req.metadata_size / sector_size) as u64;
    let footer_sectors = req.use_footer as u64 * rs;
    let header_sectors = req.use_header as u64 * rs;
    let data_sectors = total_sectors.saturating_sub(header_sectors + footer_sectors);
    let offset_sector = header_sectors;
    crate::driver_println!(
        "jvck_prepare: data_sectors={} offset_sector={} rs={}", data_sectors, offset_sector, rs
    );

    // Compute replica LBAs for metadata write (done AFTER unlock below).
    let replica_lbas: alloc::vec::Vec<u64> = {
        let mut v = alloc::vec::Vec::new();
        for i in 0..req.use_header as u64 {
            v.push(i * rs);
        }
        let footer_start = total_sectors - (req.use_footer as u64 * rs);
        for j in 0..req.use_footer as u64 {
            v.push(footer_start + j * rs + rs - 1);
        }
        v
    };

    // ── Step 3: attach filter (while still locked — prevents race re-mount) ─
    let target_do: PDO = if let Some(h) = vol_handle {
        let mut fobj: PFILE_OBJECT = null_mut();
        let st = unsafe {
            ObReferenceObjectByHandle(h, 0, null_mut(), 0,
                (&mut fobj as *mut PFILE_OBJECT).cast(), null_mut())
        };
        if crate::nt::nt_success(st) && !fobj.is_null() {
            let do_ptr = unsafe { IoGetRelatedDeviceObject(fobj) };
            unsafe { ObfDereferenceObject(fobj.cast()) };
            do_ptr
        } else { null_mut() }
    } else { null_mut() };
    crate::driver_println!("jvck_prepare: target_do={:p}", target_do);

    let (filter_do, _lower_do) = if !target_do.is_null() {
        crate::filter::attach_filter_to_raw_device(driver, target_do)
    } else {
        let win32_nt = win32_volume_path_to_nt(&req.volume_path);
        crate::filter::attach_filter_unbound(driver, &win32_nt)
    }.map_err(|err| {
        crate::driver_println!("jvck_prepare: attach failed: {}", err);
        if held_lock { if let Some(h) = vol_handle { send_fsctl(h, FSCTL_UNLOCK_VOLUME); } }
        if let Some(h) = vol_handle { unsafe { let _ = ZwClose(h); } }
        err
    })?;

    // ── Step 4: bind provisional volume (size hiding now active) ────────────
    let volume = Arc::new(AttachedVolume {
        volume_path: req.volume_path.clone(),
        sector_size,
        io_config: IoConfig::AesXts {
            key1: [0u8; 32],
            key2: [0u8; 32],
            offset_sector,
            encrypted_offset: vck_common::types::EncryptedOffset {
                sector: 0, total_sectors: data_sectors,
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
        cipher: None,
        sweep_io: Mutex::new(Arc::new(DummySectorIo { sector_size, total_sectors: data_sectors })),
        encrypted_boundary: AtomicU64::new(0),
    });
    registry.insert(volume.clone());
    unsafe { crate::filter::filter_bind_volume(filter_do, volume.clone()) };
    crate::driver_println!("jvck_prepare: provisional volume bound, size hiding active");

    // ── Step 5: unlock → FSD re-mounts above our filter ─────────────────────
    if held_lock {
        if let Some(h) = vol_handle {
            let st = send_fsctl(h, FSCTL_UNLOCK_VOLUME);
            crate::driver_println!("jvck_prepare: UNLOCK=0x{:08x}", st);
        }
    }
    if let Some(h) = vol_handle { unsafe { let _ = ZwClose(h); } }

    // ── Step 6: write metadata_block to replica LBAs (AFTER unlock) ─────────
    // The filter is now bound with size hiding active. NTFS has re-mounted and
    // sees only the data region (20971008 sectors). Replica LBAs (e.g. 20971519)
    // are OUTSIDE NTFS's view, so NTFS has never cached them. ZwWriteFile with
    // FILE_NO_INTERMEDIATE_BUFFERING (set in KernelVolumeIo::open) goes through
    // NTFS extended-DASD → filter (KernelMode pass-through) → raw device → disk.
    if !req.metadata_block.is_empty() {
        use vck_common::jvck::metadata::METADATA_BLOCK_SIZE;
        if req.metadata_block.len() < METADATA_BLOCK_SIZE {
            registry.remove(&req.volume_path);
            crate::filter::detach_filter(filter_do);
            return Err(VckError::InvalidData("metadata_block must be at least 512 bytes"));
        }
        let write_vol_id = VolumeId {
            partition_guid: Guid::nil(),
            device_path: nt_path.clone(),
        };
        match KernelVolumeIo::open(&write_vol_id, sector_size, total_sectors) {
            Ok(write_io) => {
                let mut sector_buf = alloc::vec![0u8; sector_size as usize];
                let copy_len = METADATA_BLOCK_SIZE.min(sector_size as usize);
                sector_buf[..copy_len].copy_from_slice(&req.metadata_block[..copy_len]);
                for lba in &replica_lbas {
                    match write_io.write_sectors(*lba, &sector_buf) {
                        Ok(()) => crate::driver_println!(
                            "jvck_prepare: wrote metadata lba={}", lba
                        ),
                        Err(err) => {
                            crate::driver_println!(
                                "jvck_prepare: write failed lba={}: {}", lba, err
                            );
                            registry.remove(&req.volume_path);
                            crate::filter::detach_filter(filter_do);
                            return Err(err);
                        }
                    }
                }
            }
            Err(err) => {
                crate::driver_println!("jvck_prepare: write_io open failed: {}", err);
                registry.remove(&req.volume_path);
                crate::filter::detach_filter(filter_do);
                return Err(err);
            }
        }
    }

    // Encrypt sector 0 (VBR) in the kernel while the volume is locked+dismounted.
    // PartMgr blocks writes to partition sector 0 of MOUNTED partitions; writing
    // while dismounted bypasses that check entirely.
    //
    // The FVEK is recovered from metadata_block + vmk. The metadata_block encodes
    // encrypted_offset=1, so after PREPARE the sweep starts from sector 1.
    if !req.metadata_block.is_empty() && !req.vmk.is_empty() {
        use vck_common::jvck::metadata;
        use crate::crypto::aes_xts::AesXtsCipher;
        match metadata::decrypt_payload(&req.metadata_block[..metadata::METADATA_BLOCK_SIZE.min(req.metadata_block.len())], &req.vmk) {
            Ok((_initial_offset, secrets)) => {
                match AesXtsCipher::new(secrets.fvek_key1, secrets.fvek_key2) {
                    Ok(cipher) => {
                        let write_vol_id = VolumeId {
                            partition_guid: Guid::nil(),
                            device_path: nt_path.clone(),
                        };
                        match KernelVolumeIo::open(&write_vol_id, sector_size, total_sectors) {
                            Ok(write_io) => {
                                let mut s0 = alloc::vec![0u8; sector_size as usize];
                                match write_io.read_sectors(0, &mut s0) {
                                    Ok(()) => {
                                        cipher.encrypt_sector(0, &mut s0);
                                        match write_io.write_sectors(0, &s0) {
                                            Ok(()) => crate::driver_println!("jvck_prepare: sector 0 encrypted and written"),
                                            Err(e) => crate::driver_println!("jvck_prepare: sector 0 write err: {}", e),
                                        }
                                    }
                                    Err(e) => crate::driver_println!("jvck_prepare: sector 0 read err: {}", e),
                                }
                            }
                            Err(e) => crate::driver_println!("jvck_prepare: sector 0 io open err: {}", e),
                        }
                    }
                    Err(e) => crate::driver_println!("jvck_prepare: cipher init err: {}", e),
                }
            }
            Err(e) => crate::driver_println!("jvck_prepare: metadata decrypt err: {}", e),
        }
    }

    // Query STORAGE_DEVICE_NUMBER from vol_handle_raw to find the raw partition
    // path (e.g. `\Device\Harddisk0\Partition1`) for sweep_io in ATTACH.
    // This path targets the physical disk partition below volmgr, which accepts
    // direct IoBuildSynchronousFsdRequest block I/O.
    // Query storage device number and partition start offset.
    // raw_partition_path: for metadata I/O fallback
    // raw_disk_path + partition_start_lba: for sweep_io (bypasses PartMgr sector-0 protection)
    let (raw_partition_path, raw_disk_path, partition_start_lba) = {
        use wdk_sys::ntddk::{ZwClose, ZwDeviceIoControlFile};
        // IOCTL_STORAGE_GET_DEVICE_NUMBER: CTL_CODE(FILE_DEVICE_MASS_STORAGE=0x2D, 0x420, METHOD_BUFFERED, FILE_ANY_ACCESS)
        const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;
        // IOCTL_DISK_GET_PARTITION_INFO_EX: CTL_CODE(FILE_DEVICE_DISK=7, 0x12, METHOD_BUFFERED, FILE_ANY_ACCESS)
        const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048;

        // STORAGE_DEVICE_NUMBER { DeviceType: u32, DeviceNumber: u32, PartitionNumber: u32 }
        let mut sdn = [0u32; 3];
        // PARTITION_INFORMATION_EX: PartitionStyle(4) + StartingOffset(8) + PartitionLength(8) + ...
        // We only need the first 20 bytes: style(4) + StartingOffset(8) + PartitionLength(8)
        let mut partition_info = [0u8; 64];
        let mut disk_num = 0u32;
        let mut part_num = 0u32;
        let mut start_offset_bytes: u64 = 0;

        if let Some(h) = open_volume_handle_raw(&nt_path) {
            let mut iosb: wdk_sys::IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
            let st1 = unsafe {
                ZwDeviceIoControlFile(h, null_mut(), None, null_mut(), &mut iosb,
                    IOCTL_STORAGE_GET_DEVICE_NUMBER, null_mut(), 0,
                    sdn.as_mut_ptr().cast(), 12)
            };
            if crate::nt::nt_success(st1) {
                disk_num = sdn[1];
                part_num = sdn[2];
            }
            let st2 = unsafe {
                ZwDeviceIoControlFile(h, null_mut(), None, null_mut(), &mut iosb,
                    IOCTL_DISK_GET_PARTITION_INFO_EX, null_mut(), 0,
                    partition_info.as_mut_ptr().cast(), 64)
            };
            if crate::nt::nt_success(st2) {
                // PartitionStyle(4 bytes) + StartingOffset(8 bytes) at offset 4
                start_offset_bytes = u64::from_le_bytes(
                    partition_info[4..12].try_into().unwrap_or([0;8])
                );
            }
            crate::driver_println!(
                "jvck_prepare: disk={} part={} start_offset={}",
                disk_num, part_num, start_offset_bytes
            );
            unsafe { let _ = ZwClose(h); }
        }

        let partition_path = if disk_num > 0 || part_num > 0 {
            alloc::format!(r"\Device\Harddisk{}\Partition{}", disk_num, part_num)
        } else { String::new() };
        let disk_path = if disk_num > 0 || part_num > 0 {
            alloc::format!(r"\Device\Harddisk{}\DR0", disk_num)
        } else { String::new() };
        let start_lba = start_offset_bytes / sector_size as u64;

        (partition_path, disk_path, start_lba)
    };
    crate::driver_println!(
        "jvck_prepare: raw_partition={} raw_disk={} start_lba={}",
        raw_partition_path, raw_disk_path, partition_start_lba
    );

    // If VMK was provided, complete the full attach now: read metadata, build
    // cipher, configure sweep_io, and replace the provisional volume.
    // This merges the old two-IOCTL flow (PREPARE + ATTACH) into one.
    if !req.vmk.is_empty() && !req.metadata_block.is_empty() {
        let io_nt_path = if !req.nt_device_path.is_empty() {
            req.nt_device_path.clone()
        } else {
            win32_volume_path_to_nt(&req.volume_path)
        };
        let io_volume_id = VolumeId {
            partition_guid: Guid::nil(),
            device_path: io_nt_path.clone(),
        };

        // Read metadata via KernelVolumeIo (NTFS has remounted above filter).
        let probe_io = KernelVolumeIo::open_query(&io_volume_id).map_err(|err| {
            crate::driver_println!("jvck_prepare: probe failed: {}, detaching", err);
            registry.remove(&req.volume_path);
            crate::filter::detach_filter(filter_do);
            err
        })?;
        let partition_total = probe_io.total_sectors();
        crate::driver_println!("jvck_prepare: probe ok total={}", partition_total);

        let store = JvckMetadataStore::open(probe_io, &req.vmk).map_err(|err| {
            crate::driver_println!("jvck_prepare: metadata open failed: {}, detaching", err);
            registry.remove(&req.volume_path);
            crate::filter::detach_filter(filter_do);
            err
        })?;

        let store_offset = store.offset_sector();
        let store_data = store.data_sector_count();
        let store_bps = store.sector_size();
        let encrypted_offset = EncryptedOffset {
            sector: store.load_offset()?,
            total_sectors: store_data,
        };
        let (key1, key2) = store.fvek_keys();
        let (key1, key2) = (*key1, *key2);
        let offset_store: Arc<dyn EncryptedOffsetStore> = Arc::new(store);
        let io_config = IoConfig::AesXts {
            key1, key2,
            offset_sector: store_offset,
            encrypted_offset: encrypted_offset.clone(),
            offset_store: offset_store.clone(),
        };
        let cipher = AesXtsCipher::new(key1, key2).map_err(|err| {
            registry.remove(&req.volume_path);
            crate::filter::detach_filter(filter_do);
            err
        })?;

        // sweep_io: prefer raw disk (bypass PartMgr), fall back to partition path.
        let sweep_io: Arc<dyn SectorIo> = if !raw_disk_path.is_empty() && partition_start_lba > 0 {
            let disk_id = VolumeId { partition_guid: Guid::nil(), device_path: raw_disk_path.clone() };
            let disk_total = partition_start_lba + store_data + 1024;
            crate::driver_println!("jvck_prepare: sweep via raw disk {} lba={}", raw_disk_path, partition_start_lba);
            let disk_io = KernelVolumeIo::open(&disk_id, store_bps, disk_total).map_err(|e| {
                registry.remove(&req.volume_path);
                crate::filter::detach_filter(filter_do);
                e
            })?;
            Arc::new(OffsetSectorIo::new(Arc::new(disk_io) as Arc<dyn SectorIo>, partition_start_lba))
        } else if !raw_partition_path.is_empty() {
            let part_id = VolumeId { partition_guid: Guid::nil(), device_path: raw_partition_path.clone() };
            crate::driver_println!("jvck_prepare: sweep via raw partition {}", raw_partition_path);
            Arc::new(KernelVolumeIo::open(&part_id, store_bps, store_data).map_err(|e| {
                registry.remove(&req.volume_path);
                crate::filter::detach_filter(filter_do);
                e
            })?)
        } else {
            Arc::new(KernelVolumeIo::open(&io_volume_id, store_bps, store_data).map_err(|e| {
                registry.remove(&req.volume_path);
                crate::filter::detach_filter(filter_do);
                e
            })?)
        };

        registry.remove(&req.volume_path);
        let initial_boundary = encrypted_offset.sector;
        let complete_volume = Arc::new(AttachedVolume {
            volume_path: req.volume_path.clone(),
            sector_size: store_bps,
            io_config,
            encryption: Mutex::new(EncryptionEngine::new(store_offset, encrypted_offset)),
            offset_store,
            attach_source: AttachSource::Ioctl,
            filter_device: AtomicPtr::new(filter_do),
            cipher: Some(cipher),
            sweep_io: Mutex::new(sweep_io),
            encrypted_boundary: AtomicU64::new(initial_boundary),
        });
        registry.insert(complete_volume.clone());
        unsafe { crate::filter::filter_rebind_volume(filter_do, complete_volume) };
        crate::driver_println!("jvck_prepare: fully attached offset={} data={}", store_offset, store_data);

        return encode_resp(&JvckVolumePrepareResp {
            offset_sector: store_offset,
            data_sectors: store_data,
            sector_size: store_bps,
            raw_partition_path, raw_disk_path, partition_start_lba,
            fully_attached: true,
        });
    }

    encode_resp(&JvckVolumePrepareResp {
        offset_sector, data_sectors, sector_size,
        raw_partition_path, raw_disk_path, partition_start_lba,
        fully_attached: false,
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

    // sweep_io must bypass both NTFS and the filter so that:
    //   1. NTFS write protection for its own sectors (e.g. VBR at lba=0) doesn't block us
    //   2. The filter doesn't double-encrypt already-in-memory-encrypted data
    //
    // `lower_do` (HarddiskVolume5) is managed by volmgr and may reject raw writes to
    // NTFS-protected sectors (returns STATUS_ACCESS_DENIED for lba=0).
    // `lower_do->Vpb->RealDevice` is the underlying partition device (e.g.
    // \Device\Harddisk0\Partition1) which accepts all sector-aligned writes from
    // kernel mode without NTFS or volume-manager protection.
    // Get the raw partition device (Vpb->RealDevice of the volume device below
    // our filter) for sweep_io. This bypasses NTFS and HarddiskVolume5's
    // write protection (HarddiskVolume5 refuses raw writes to NTFS-protected
    // sectors like lba=0 with STATUS_ACCESS_DENIED).
    // Re-attach: sector 0 was already encrypted during the original PREPARE, so
    // sweep starts from sector 1. Use raw partition path to bypass NTFS protection.
    let sweep_io: Arc<dyn SectorIo> = if !req.raw_partition_path.is_empty() {
        let part_id = VolumeId {
            partition_guid: Guid::nil(),
            device_path: req.raw_partition_path.clone(),
        };
        crate::driver_println!("jvck_attach: sweep_io via raw partition {}", req.raw_partition_path);
        Arc::new(KernelVolumeIo::open(&part_id, store_sector_size, store_data_sectors)?)
    } else {
        crate::driver_println!("jvck_attach: sweep_io via volume (no raw path)");
        Arc::new(KernelVolumeIo::open(&io_volume_id, store_sector_size, store_data_sectors)?)
    };

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
