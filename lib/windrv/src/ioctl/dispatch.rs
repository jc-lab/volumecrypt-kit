// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! IRP_MJ_DEVICE_CONTROL handler. Authorizes, then routes by IOCTL code.
//!
//! GET_PROGRESS is non-blocking: it returns the current snapshot immediately.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use spin::Mutex;
use vck_common::{
    types::Guid, EncryptedOffsetStore, SectorIo, VckError, VckResult, VolumeId,
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
    BenchAesReq, BenchAesResp, JvckVolumeAttachReq, JvckVolumeAttachResp,
    JvckVolumePrepareReq, JvckVolumePrepareResp, ProgressEvent, VolumeListEntry,
    VolumeListResponse, VolumeRequest, VolumeStatus,
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
    crate::vck_log!(
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
        IOCTL_VCK_PAUSE_OS_VOLUME => handle_pause_os_volume(registry),
        IOCTL_VCK_DETACH_ALL_VOLUMES => handle_detach_all_volumes(registry),
        IOCTL_VCK_BENCH_AES => handle_bench_aes(input),
        IOCTL_VCK_LIST_VOLUMES => handle_list_volumes(registry),
        _ => Err(VckError::Unsupported("unknown IOCTL code")),
    }
}

#[derive(Serialize)]
struct EmptyResponse {}

/// Bind a volume by delegating to the sample's `VolumeProvider::on_attach`
/// (installed at `DriverEntry` via `set_volume_provider`). `io` is an owning
/// `SectorIo` over the volume's data path; the sample opens + decrypts the
/// metadata over it (and may read vendor-specific data), builds the cipher, and
/// returns the `IoConfig`. The framework owns no crypto policy of its own.
fn on_attach_volume(
    vmk: &[u8],
    partition_guid: Option<Guid>,
    io: Arc<dyn SectorIo>,
) -> VckResult<IoConfig> {
    let provider = crate::provider::global_volume_provider()
        .ok_or(VckError::ValidationFailed("no volume provider installed"))?;
    let ctx = crate::provider::AttachContext {
        io,
        vmk,
        partition_guid,
    };
    provider.on_attach(&ctx)
}

/// Resolve an attached volume by the app-supplied path.
///
/// Data volumes are keyed by the exact path the app sent (direct lookup works).
/// The OS (handover) volume is keyed by its NT device name (chosen by the driver
/// at handover bind), which differs from the canonical/Win32 path the app queries
/// with — so on a miss we resolve the path to its filter device and match the
/// volume by that.
fn resolve_volume(
    registry: &VolumeAttachRegistry,
    volume_path: &str,
) -> Option<Arc<AttachedVolume>> {
    if let Some(v) = registry.get(volume_path) {
        return Some(v);
    }
    let nt_path = win32_volume_path_to_nt(volume_path);
    let (filter_do, _lower) = crate::filter::find_filter_for_volume(
        &nt_path,
        |dev| registry.find_pdo_filter(dev),
        |name| registry.find_pdo_filter_by_name(name),
    )?;
    registry.get_by_filter(filter_do)
}

fn handle_get_status(registry: &VolumeAttachRegistry, input: &[u8]) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    let nt_path = win32_volume_path_to_nt(&req.volume_path);

    // Check if our filter is correctly placed BELOW the FSD (AddDevice path).
    // This is true when find_our_filter_in_stack succeeds: means NTFS VCB is
    // above our filter in the device stack.
    let filter_below_fsd = crate::filter::find_filter_for_volume(
        &nt_path,
        |dev| registry.find_pdo_filter(dev),
        |name| registry.find_pdo_filter_by_name(name),
    ).is_some();

    if let Some(volume) = resolve_volume(registry, &req.volume_path) {
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

/// List every attached volume. Takes no input; an empty list still confirms the
/// driver is reachable (the app uses this to verify the connection without
/// knowing a specific volume path).
fn handle_list_volumes(registry: &VolumeAttachRegistry) -> VckResult<IoctlResponse> {
    let volumes = registry
        .all()
        .iter()
        .map(|v| {
            let snapshot = v.encryption.lock().snapshot();
            VolumeListEntry {
                volume_path: v.volume_path.clone(),
                state: snapshot.state.as_wire(),
                encrypted_sector: snapshot.encrypted_sector,
                total_sectors: snapshot.total_sectors,
                sector_size: v.sector_size,
                is_os_volume: v.is_os_volume(),
            }
        })
        .collect();
    encode_resp(&VolumeListResponse { volumes })
}

fn handle_start_encrypt(
    registry: &VolumeAttachRegistry,
    input: &[u8],
) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    let volume = resolve_volume(registry, &req.volume_path)
        .ok_or(VckError::NotFound("volume is not attached"))?;
    volume.encryption.lock().start_encrypt(&*volume.offset_store);
    unsafe { crate::filter::volume_thread::wake_for(&volume) };
    encode_resp(&EmptyResponse {})
}

fn handle_start_decrypt(
    registry: &VolumeAttachRegistry,
    input: &[u8],
) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    let volume = resolve_volume(registry, &req.volume_path)
        .ok_or(VckError::NotFound("volume is not attached"))?;
    volume.encryption.lock().start_decrypt(&*volume.offset_store);
    unsafe { crate::filter::volume_thread::wake_for(&volume) };
    encode_resp(&EmptyResponse {})
}

fn handle_get_progress(
    registry: &VolumeAttachRegistry,
    input: &[u8],
) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    let volume = resolve_volume(registry, &req.volume_path)
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
    let volume = resolve_volume(registry, &req.volume_path)
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
    use vck_common::jvck::metadata::METADATA_BLOCK_SIZE;
    use wdk_sys::ntddk::ZwDeviceIoControlFile;

    // OS (system) volumes register as Handover so DETACH_ALL / detach / unload
    // protections apply — the same volume the boot loader re-attaches.
    let attach_source = if req.is_os_volume {
        AttachSource::Handover
    } else {
        AttachSource::Ioctl
    };

    // Query geometry (NTFS is mounted, ZwCreateFile works via existing filter pass-through).
    let io_volume_id = VolumeId { partition_guid: Guid::nil(), device_path: nt_path.clone() };
    let geom_io = KernelVolumeIo::open_query(&io_volume_id).map_err(|e| {
        crate::vck_log!("jvck_prepare(add): geom open failed: {}", e);
        e
    })?;
    let sector_size = geom_io.sector_size();
    let total_sectors = geom_io.total_sectors();
    crate::vck_log!("jvck_prepare(add): bps={} total={}", sector_size, total_sectors);
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
                crate::vck_log!("jvck_prepare(add): metadata write lba={} err: {}", lba, e);
                e
            })?;
            crate::vck_log!("jvck_prepare(add): wrote metadata lba={}", lba);
        }
    }

    // Sector 0 (VBR) will be encrypted by the sweep via LowerDeviceIo (which
    // bypasses PartMgr protection). No pre-encryption needed here.

    // Bind provisional volume (size hiding active).
    let volume = Arc::new(AttachedVolume {
        volume_path: req.volume_path.clone(),
        sector_size,
        io_config: IoConfig::Encrypted {
            cipher: None,
            offset_sector,
            encrypted_offset: vck_common::types::EncryptedOffset { sector: 0, total_sectors: data_sectors },
            offset_store: Arc::new(DummyOffsetStore { total_sectors: data_sectors }),
        },
        encryption: Mutex::new(EncryptionEngine::new(
            offset_sector,
            vck_common::types::EncryptedOffset { sector: 0, total_sectors: data_sectors },
        )),
        offset_store: Arc::new(DummyOffsetStore { total_sectors: data_sectors }),
        attach_source,
        filter_device: AtomicPtr::new(filter_do),
        sweep_io: Mutex::new(Arc::new(DummySectorIo { sector_size, total_sectors: data_sectors })),
        encrypted_boundary: AtomicU64::new(0),
    });
    registry.insert(volume.clone());
    unsafe { crate::filter::filter_bind_volume(filter_do, volume.clone()) };
    crate::vck_log!("jvck_prepare(add): provisional volume bound (AddDevice path)");

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
    // This fires even when `metadata_block` is empty (re-attach of a volume whose
    // metadata is already on disk): the footer is read here via LowerDeviceIo at
    // the FULL partition size, so it is found at the true last sector — unlike the
    // separate IOCTL_JVCK_ATTACH path, which reads through the size-hiding filter
    // and would look at the wrong (data-region-end) LBA.
    if !req.vmk.is_empty() {
        // Use LowerDeviceIo to read metadata. This bypasses:
        // 1. The filter (which now applies size hiding, reporting 20971008 sectors)
        // 2. NTFS (which might cache/remap sectors)
        // The raw partition has the metadata at the full partition's last sector.
        // Let the SAMPLE open + decrypt the metadata over the lower device and
        // build the cipher. The probe IO is shared (Arc) so the sample's store
        // owns one clone while we keep none here.
        let probe_io: Arc<dyn SectorIo> =
            Arc::new(LowerDeviceIo::new(lower_do, sector_size, total_sectors));
        let io_config = on_attach_volume(&req.vmk, None, probe_io).map_err(|e| {
            registry.remove(&req.volume_path);
            crate::filter::detach_filter(filter_do);
            e
        })?;
        let (store_offset, encrypted_offset, offset_store) =
            io_config.geometry().ok_or(VckError::ValidationFailed(
                "on_attach returned passthrough for a VMK-provided volume",
            ))?;
        let store_data = encrypted_offset.total_sectors;
        let store_bps = sector_size;
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
            attach_source,
            filter_device: AtomicPtr::new(filter_do),
            sweep_io: Mutex::new(sweep_io),
            encrypted_boundary: AtomicU64::new(boundary),
        });
        registry.insert(complete.clone());
        unsafe { crate::filter::filter_rebind_volume(filter_do, complete) };
        crate::vck_log!("jvck_prepare(add): fully attached offset={} data={}", store_offset, store_data);
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

    crate::vck_log!(
        "jvck_prepare: enter stack={}",
        crate::debug::remaining_stack()
    );
    let req: JvckVolumePrepareReq = decode_req(input)?;
    crate::vck_log!(
        "jvck_prepare: path={} use_h={} use_f={} md_size={} block_len={} is_os={}",
        req.volume_path, req.use_header, req.use_footer, req.metadata_size,
        req.metadata_block.len(), req.is_os_volume
    );

    // OS (system) volumes register as Handover so DETACH_ALL / detach / unload
    // protections apply — the same volume the boot loader re-attaches.
    let attach_source = if req.is_os_volume {
        AttachSource::Handover
    } else {
        AttachSource::Ioctl
    };

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
    // After driver install + reboot, AddDevice has attached an unbound filter.
    // Find it via the PDO map (reliable; avoids VPB-vs-attachment ambiguity).
    if let Some((filter_do, lower_do)) = crate::filter::find_filter_for_volume(
        &nt_path,
        |dev| registry.find_pdo_filter(dev),
        |name| registry.find_pdo_filter_by_name(name),
    ) {
        crate::vck_log!(
            "jvck_prepare: AddDevice filter found filter={:p} lower={:p}",
            filter_do, lower_do
        );
        return handle_jvck_prepare_adddevice_path(
            registry, req, nt_path, driver, filter_do, lower_do,
        );
    }
    crate::vck_log!("jvck_prepare: no pre-attached filter, using lock/dismount fallback");

    // Open vol_handle early — used for FSCTLs, geometry, metadata write.
    let vol_handle = open_volume_handle_raw(&nt_path);
    crate::vck_log!("jvck_prepare: vol_handle_open={}", vol_handle.is_some());

    // ── Step 1: lock → dismount → re-lock ──────────────────────────────────
    let mut held_lock = false;
    if let Some(h) = vol_handle {
        let st = send_fsctl(h, FSCTL_LOCK_VOLUME);
        crate::vck_log!("jvck_prepare: LOCK(1)=0x{:08x}", st);
        held_lock = crate::nt::nt_success(st);
    }
    if let Some(h) = vol_handle {
        let st = send_fsctl(h, FSCTL_DISMOUNT_VOLUME);
        crate::vck_log!("jvck_prepare: DISMOUNT=0x{:08x}", st);
    }
    if !held_lock {
        if let Some(h) = vol_handle {
            let st = send_fsctl(h, FSCTL_LOCK_VOLUME);
            crate::vck_log!("jvck_prepare: LOCK(2)=0x{:08x}", st);
            held_lock = crate::nt::nt_success(st);
        }
    }
    crate::vck_log!("jvck_prepare: lock_held={}", held_lock);

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
        crate::vck_log!("jvck_prepare: geom bps={} total={}", bps, total);
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
    crate::vck_log!(
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
    crate::vck_log!("jvck_prepare: target_do={:p}", target_do);

    let (filter_do, _lower_do) = if !target_do.is_null() {
        crate::filter::attach_filter_to_raw_device(driver, target_do)
    } else {
        let win32_nt = win32_volume_path_to_nt(&req.volume_path);
        crate::filter::attach_filter_unbound(driver, &win32_nt)
    }.map_err(|err| {
        crate::vck_log!("jvck_prepare: attach failed: {}", err);
        if held_lock { if let Some(h) = vol_handle { send_fsctl(h, FSCTL_UNLOCK_VOLUME); } }
        if let Some(h) = vol_handle { unsafe { let _ = ZwClose(h); } }
        err
    })?;

    // ── Step 4: bind provisional volume (size hiding now active) ────────────
    let volume = Arc::new(AttachedVolume {
        volume_path: req.volume_path.clone(),
        sector_size,
        io_config: IoConfig::Encrypted {
            cipher: None,
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
        attach_source,
        filter_device: AtomicPtr::new(filter_do),
        sweep_io: Mutex::new(Arc::new(DummySectorIo { sector_size, total_sectors: data_sectors })),
        encrypted_boundary: AtomicU64::new(0),
    });
    registry.insert(volume.clone());
    unsafe { crate::filter::filter_bind_volume(filter_do, volume.clone()) };
    crate::vck_log!("jvck_prepare: provisional volume bound, size hiding active");

    // ── Step 5: unlock → FSD re-mounts above our filter ─────────────────────
    if held_lock {
        if let Some(h) = vol_handle {
            let st = send_fsctl(h, FSCTL_UNLOCK_VOLUME);
            crate::vck_log!("jvck_prepare: UNLOCK=0x{:08x}", st);
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
                        Ok(()) => crate::vck_log!(
                            "jvck_prepare: wrote metadata lba={}", lba
                        ),
                        Err(err) => {
                            crate::vck_log!(
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
                crate::vck_log!("jvck_prepare: write_io open failed: {}", err);
                registry.remove(&req.volume_path);
                crate::filter::detach_filter(filter_do);
                return Err(err);
            }
        }
    }

    // Sector 0 (VBR) is handled by the sweep (via LowerDeviceIo in AddDevice path
    // or KernelVolumeIo while dismounted in fallback path).
    // The metadata_block uses encrypted_offset=0 so the sweep starts from sector 0.

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
            crate::vck_log!(
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
    crate::vck_log!(
        "jvck_prepare: raw_partition={} raw_disk={} start_lba={}",
        raw_partition_path, raw_disk_path, partition_start_lba
    );

    // If VMK was provided, complete the full attach now: read metadata, build
    // cipher, configure sweep_io, and replace the provisional volume.
    // This merges the old two-IOCTL flow (PREPARE + ATTACH) into one, and also
    // handles re-attach (empty metadata_block) since the metadata is read from
    // disk here, not from the request.
    if !req.vmk.is_empty() {
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
            crate::vck_log!("jvck_prepare: probe failed: {}, detaching", err);
            registry.remove(&req.volume_path);
            crate::filter::detach_filter(filter_do);
            err
        })?;
        let partition_total = probe_io.total_sectors();
        let store_bps = probe_io.sector_size();
        crate::vck_log!("jvck_prepare: probe ok total={}", partition_total);

        // Let the SAMPLE open + decrypt the metadata over the probe IO and build
        // the cipher; the framework owns no crypto policy.
        let probe_arc: Arc<dyn SectorIo> = Arc::new(probe_io);
        let io_config = on_attach_volume(&req.vmk, None, probe_arc).map_err(|err| {
            crate::vck_log!("jvck_prepare: on_attach failed: {}, detaching", err);
            registry.remove(&req.volume_path);
            crate::filter::detach_filter(filter_do);
            err
        })?;
        let (store_offset, encrypted_offset, offset_store) =
            io_config.geometry().ok_or(VckError::ValidationFailed(
                "on_attach returned passthrough for a VMK-provided volume",
            ))?;
        let store_data = encrypted_offset.total_sectors;

        // sweep_io: prefer raw disk (bypass PartMgr), fall back to partition path.
        let sweep_io: Arc<dyn SectorIo> = if !raw_disk_path.is_empty() && partition_start_lba > 0 {
            let disk_id = VolumeId { partition_guid: Guid::nil(), device_path: raw_disk_path.clone() };
            let disk_total = partition_start_lba + store_data + 1024;
            crate::vck_log!("jvck_prepare: sweep via raw disk {} lba={}", raw_disk_path, partition_start_lba);
            let disk_io = KernelVolumeIo::open(&disk_id, store_bps, disk_total).map_err(|e| {
                registry.remove(&req.volume_path);
                crate::filter::detach_filter(filter_do);
                e
            })?;
            Arc::new(OffsetSectorIo::new(Arc::new(disk_io) as Arc<dyn SectorIo>, partition_start_lba))
        } else if !raw_partition_path.is_empty() {
            let part_id = VolumeId { partition_guid: Guid::nil(), device_path: raw_partition_path.clone() };
            crate::vck_log!("jvck_prepare: sweep via raw partition {}", raw_partition_path);
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
            attach_source,
            filter_device: AtomicPtr::new(filter_do),
            sweep_io: Mutex::new(sweep_io),
            encrypted_boundary: AtomicU64::new(initial_boundary),
        });
        registry.insert(complete_volume.clone());
        unsafe { crate::filter::filter_rebind_volume(filter_do, complete_volume) };
        crate::vck_log!("jvck_prepare: fully attached offset={} data={}", store_offset, store_data);

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
    crate::vck_log!(
        "jvck_attach: enter stack={}",
        crate::debug::remaining_stack()
    );
    let req: JvckVolumeAttachReq = decode_req(input)?;
    crate::vck_log!(
        "jvck_attach: path={} vmk_len={}",
        req.volume_path, req.vmk.len()
    );

    // ATTACH (phase 2) is the data-volume re-attach path; OS volumes complete via
    // PREPARE (fully_attached) instead, so this is always a data volume.
    let attach_source = AttachSource::Ioctl;

    // Find the provisional volume created by PREPARE (has cipher=None).
    let provisional = registry
        .get(&req.volume_path)
        .ok_or(VckError::NotFound("volume not prepared; call IOCTL_JVCK_PREPARE first"))?;

    if provisional.cipher().is_some() {
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
        crate::vck_log!("jvck_attach: probe open_query failed: {}", err);
        err
    })?;
    let partition_total = probe_io.total_sectors();
    crate::vck_log!(
        "jvck_attach: partition_total={} sector_size={}",
        partition_total, probe_io.sector_size()
    );

    // Diagnostic: print footer bytes.
    {
        let footer_lba = partition_total.saturating_sub(1);
        let mut diag = alloc::vec![0u8; probe_io.sector_size() as usize];
        if probe_io.read_sectors(footer_lba, &mut diag).is_ok() {
            crate::vck_log!(
                "jvck_attach: footer_lba={} bytes=[{:02x}{:02x}{:02x}{:02x} {:02x}{:02x}{:02x}{:02x}]",
                footer_lba,
                diag[0], diag[1], diag[2], diag[3],
                diag[4], diag[5], diag[6], diag[7]
            );
        }
    }

    let store_sector_size = probe_io.sector_size();
    // Let the SAMPLE open + decrypt the metadata over the probe IO and build the
    // cipher; the framework owns no crypto policy.
    let probe_arc: Arc<dyn SectorIo> = Arc::new(probe_io);
    let io_config = on_attach_volume(&req.vmk, None, probe_arc).map_err(|err| {
        crate::vck_log!("jvck_attach: on_attach failed: {}", err);
        err
    })?;
    crate::vck_log!("jvck_attach: metadata opened");

    let (offset_sector, encrypted_offset, offset_store) =
        io_config.geometry().ok_or(VckError::ValidationFailed(
            "on_attach returned passthrough for a VMK-provided volume",
        ))?;
    let store_data_sectors = encrypted_offset.total_sectors;

    crate::vck_log!("jvck_attach: build sweep_io");

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
        crate::vck_log!("jvck_attach: sweep_io via raw partition {}", req.raw_partition_path);
        Arc::new(KernelVolumeIo::open(&part_id, store_sector_size, store_data_sectors)?)
    } else {
        crate::vck_log!("jvck_attach: sweep_io via volume (no raw path)");
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
        attach_source,
        filter_device: AtomicPtr::new(filter_do),
        sweep_io: Mutex::new(sweep_io),
        encrypted_boundary: AtomicU64::new(initial_boundary),
    });
    registry.insert(volume.clone());
    unsafe { crate::filter::filter_rebind_volume(filter_do, volume.clone()) };
    crate::vck_log!("jvck_attach: volume complete and rebound, done");

    encode_resp(&JvckVolumeAttachResp {
        offset_sector,
        total_sectors: store_data_sectors,
        sector_size: store_sector_size,
    })
}

/// Cleanly detach an encrypted volume:
///   1. FSCTL_LOCK_VOLUME (if `ignore_open_files`, failure is non-fatal)
///   2. FSCTL_DISMOUNT_VOLUME (retry up to `max_dismount_retries`, 100 ms between attempts)
///   3. Filter teardown — `unbind_filter` (pass-through, re-attachable) when
///      `keep_filter`, else `detach_filter` (full delete, for unload/shutdown).
///
/// Must be called on an EXPANDED kernel stack (uses KeDelayExecutionThread).
pub fn detach_volume_with_dismount(
    registry: &VolumeAttachRegistry,
    volume_path: &str,
    ignore_open_files: bool,
    keep_filter: bool,
) -> VckResult<()> {
    use crate::io::{open_volume_handle_raw, send_fsctl};
    use wdk_sys::ntddk::{KeDelayExecutionThread, ZwClose};
    use wdk_sys::LARGE_INTEGER;
    const FSCTL_LOCK_VOLUME: u32 = 0x0009_0018;
    const FSCTL_DISMOUNT_VOLUME: u32 = 0x0009_0020;
    const FSCTL_UNLOCK_VOLUME: u32 = 0x0009_001c;
    const MAX_RETRIES: u32 = 100;
    // -100_0000 * 100 ns = 100 ms (relative, negative = relative time)
    const DELAY_100MS: i64 = -1_000_000;

    let volume = registry
        .remove(volume_path)
        .ok_or(VckError::NotFound("volume is not attached"))?;

    let filter_do = volume.filter_device.swap(null_mut(), Ordering::AcqRel);
    let nt_path = win32_volume_path_to_nt(volume_path);

    let vol_handle = open_volume_handle_raw(&nt_path);
    let mut held_lock = false;

    if let Some(h) = vol_handle {
        // Step 1: lock (non-fatal if ignore_open_files).
        let lock_st = send_fsctl(h, FSCTL_LOCK_VOLUME);
        crate::vck_log!("detach: LOCK_VOLUME=0x{:08x} ignore={}", lock_st, ignore_open_files);
        if crate::nt::nt_success(lock_st) {
            held_lock = true;
        } else if !ignore_open_files {
            unsafe { let _ = ZwClose(h); }
            return Err(VckError::Io("FSCTL_LOCK_VOLUME failed (files open)".into()));
        }

        // Step 2: dismount with retries.
        let mut dismounted = false;
        for attempt in 0..MAX_RETRIES {
            let dis_st = send_fsctl(h, FSCTL_DISMOUNT_VOLUME);
            crate::vck_log!(
                "detach: DISMOUNT_VOLUME attempt={} status=0x{:08x}", attempt, dis_st
            );
            if crate::nt::nt_success(dis_st) {
                dismounted = true;
                break;
            }
            if attempt < MAX_RETRIES - 1 {
                let mut interval = LARGE_INTEGER { QuadPart: DELAY_100MS };
                unsafe { KeDelayExecutionThread(0 /*KernelMode*/, 0 /*FALSE*/, &mut interval); }
            }
        }
        if !dismounted {
            crate::vck_log!("detach: DISMOUNT_VOLUME failed after {} retries", MAX_RETRIES);
        }

        // Unlock so the FSD (if any) can re-mount (or stays unmounted — we'll detach).
        if held_lock {
            let unlock_st = send_fsctl(h, FSCTL_UNLOCK_VOLUME);
            crate::vck_log!("detach: UNLOCK_VOLUME=0x{:08x}", unlock_st);
        }
        unsafe { let _ = ZwClose(h); }
    }

    // Brief delay to allow any in-flight IRPs on the filter to complete before
    // IoDetachDevice/IoDeleteDevice. Without this, pending completion routines
    // or I/O in progress can cause a BSOD when the filter is removed.
    {
        use wdk_sys::ntddk::KeDelayExecutionThread;
        use wdk_sys::LARGE_INTEGER;
        let mut interval = LARGE_INTEGER { QuadPart: -5_000_000 }; // 500 ms
        unsafe { KeDelayExecutionThread(0, 0, &mut interval); }
    }

    // Step 3: filter teardown. User detach keeps the filter as pass-through so
    // the volume can be re-attached without a reboot; unload/shutdown fully
    // deletes it.
    if !filter_do.is_null() {
        if keep_filter {
            crate::filter::unbind_filter(filter_do);
        } else {
            crate::filter::detach_filter(filter_do);
        }
    }
    crate::vck_log!("detach: done for {} (keep_filter={})", volume_path, keep_filter);
    Ok(())
}

fn handle_detach(registry: &VolumeAttachRegistry, input: &[u8]) -> VckResult<IoctlResponse> {
    let req: VolumeRequest = decode_req(input)?;
    // An OS (handover) volume with any encrypted sector cannot be detached: the
    // live system volume would then read ciphertext. Refuse the request.
    if let Some(volume) = registry.get(&req.volume_path) {
        if volume.is_os_volume() && volume.has_encrypted_data() {
            crate::vck_log!("detach: refused — OS volume is encrypted ({})", req.volume_path);
            return Err(VckError::PermissionDenied(
                "OS volume is encrypted; detach is not allowed",
            ));
        }
    }
    // keep_filter=true: leave the filter attached as pass-through so the volume
    // can be re-attached (mounted) again without a reboot.
    detach_volume_with_dismount(registry, &req.volume_path, false, true).map_err(|e| {
        crate::vck_log!("detach: failed: {}", e);
        e
    })?;
    encode_resp(&EmptyResponse {})
}

/// `IOCTL_VCK_PAUSE_OS_VOLUME` — pause the OS (handover) volume's background
/// sweep. The encryption boundary stops advancing (so the on-disk ciphertext
/// region stays consistent with the persisted boundary across a reboot) while
/// the filter stays BOUND, so live writes during shutdown remain encrypted.
///
/// Acquiring the engine lock blocks until any in-flight sweep batch (which holds
/// that lock for the whole read-encrypt-write-persist batch) finishes, so on
/// return no batch is running and none will start.
///
/// NOTE: does not eliminate the hard-crash (power-loss) window where a batch's
/// ciphertext is written but its boundary not yet persisted (needs hotzone
/// journaling, out of scope). It only makes graceful shutdown deterministic.
fn handle_pause_os_volume(registry: &VolumeAttachRegistry) -> VckResult<IoctlResponse> {
    for volume in registry.all() {
        if volume.is_os_volume() {
            volume.encryption.lock().pause();
            crate::vck_log!("pause_os_volume: paused {}", volume.volume_path);
        }
    }
    Ok(Vec::new())
}

/// `IOCTL_VCK_DETACH_ALL_VOLUMES` — detach every DATA (IOCTL-attached) volume.
/// OS (handover) volumes are intentionally left bound: an encrypted OS volume
/// must not be detached (detaching its filter would expose ciphertext / let
/// shutdown writes land as plaintext in the encrypted region).
fn handle_detach_all_volumes(registry: &VolumeAttachRegistry) -> VckResult<IoctlResponse> {
    let data_paths: Vec<String> = registry
        .all()
        .into_iter()
        .filter(|v| !v.is_os_volume())
        .map(|v| v.volume_path.clone())
        .collect();
    for path in data_paths {
        crate::vck_log!("detach_all_data: detaching {}", path);
        // keep_filter=false: this runs on shutdown/unload, so fully tear down the
        // filter device (IoDetachDevice + IoDeleteDevice).
        if let Err(e) = detach_volume_with_dismount(registry, &path, true, false) {
            crate::vck_log!("detach_all_data: {} failed: {}", path, e);
        }
    }
    Ok(Vec::new())
}

/// `IOCTL_VCK_BENCH_AES` — measure AES-256-XTS encrypt and decrypt throughput
/// inside the kernel. Allocates a 1 MiB NonPagedPool scratch buffer, processes
/// the requested number of bytes (default 1 GiB) in sector-sized chunks, and
/// returns MiB/s for each direction. No volume is required.
///
/// The benchmark uses an all-zero key pair (not security-sensitive; purely for
/// measuring raw cipher throughput).
fn handle_bench_aes(input: &[u8]) -> VckResult<IoctlResponse> {
    use wdk_sys::{
        ntddk::{ExAllocatePool2, ExFreePool},
        LARGE_INTEGER,
    };
    use crate::ntddk_ex::KeQueryPerformanceCounter;

    const DEFAULT_BYTES: u64 = 1u64 << 30; // 1 GiB
    const CHUNK_BYTES: usize = 1 << 20;     // 1 MiB scratch buffer
    const SECTOR_SIZE: usize = 512;
    const SECTORS_PER_CHUNK: usize = CHUNK_BYTES / SECTOR_SIZE;
    const POOL_FLAG_NON_PAGED: u64 = 0x0000_0000_0000_0040;
    const POOL_TAG: u32 = u32::from_le_bytes(*b"VCKI");

    let req: BenchAesReq = decode_req(input)?;
    let size_bytes = if req.size_bytes == 0 { DEFAULT_BYTES } else { req.size_bytes };

    let cipher = AesXtsCipher::new([0u8; 32], [0u8; 32])
        .map_err(|_| VckError::CryptoFailed("bench cipher init"))?;

    let buf =
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, CHUNK_BYTES as u64, POOL_TAG) as *mut u8 };
    if buf.is_null() {
        return Err(VckError::Io("bench: NonPagedPool alloc failed".into()));
    }
    unsafe { core::ptr::write_bytes(buf, 0u8, CHUNK_BYTES) };

    let chunks = ((size_bytes as usize + CHUNK_BYTES - 1) / CHUNK_BYTES) as u64;
    let actual_bytes = chunks * CHUNK_BYTES as u64;
    let actual_mib = actual_bytes / (1024 * 1024);

    let mut freq = LARGE_INTEGER { QuadPart: 1i64 };

    // --- Encrypt pass (8-block parallel AES-NI path) ---
    let enc_start = unsafe { KeQueryPerformanceCounter(&mut freq) };
    for ci in 0u64..chunks {
        let base_sector = ci * SECTORS_PER_CHUNK as u64;
        let slice = unsafe { core::slice::from_raw_parts_mut(buf, CHUNK_BYTES) };
        cipher.encrypt_area(slice, SECTOR_SIZE, base_sector);
    }
    let enc_end = unsafe { KeQueryPerformanceCounter(core::ptr::null_mut()) };

    // --- Decrypt pass (8-block parallel AES-NI path) ---
    let dec_start = unsafe { KeQueryPerformanceCounter(core::ptr::null_mut()) };
    for ci in 0u64..chunks {
        let base_sector = ci * SECTORS_PER_CHUNK as u64;
        let slice = unsafe { core::slice::from_raw_parts_mut(buf, CHUNK_BYTES) };
        cipher.decrypt_area(slice, SECTOR_SIZE, base_sector);
    }
    let dec_end = unsafe { KeQueryPerformanceCounter(core::ptr::null_mut()) };

    unsafe { ExFreePool(buf as *mut _) };

    // All values are positive: freq > 0, end >= start.
    let freq_val = unsafe { freq.QuadPart } as u64;
    let enc_ticks = unsafe { enc_end.QuadPart - enc_start.QuadPart } as u64;
    let dec_ticks = unsafe { dec_end.QuadPart - dec_start.QuadPart } as u64;

    let encrypt_mib_s = if enc_ticks == 0 { 0 } else { actual_mib * freq_val / enc_ticks };
    let decrypt_mib_s = if dec_ticks == 0 { 0 } else { actual_mib * freq_val / dec_ticks };

    crate::vck_log!(
        "bench_aes: size={}MiB enc={}MiB/s dec={}MiB/s",
        actual_mib,
        encrypt_mib_s,
        decrypt_mib_s,
    );

    encode_resp(&BenchAesResp {
        size_bytes: actual_bytes,
        encrypt_mib_s,
        decrypt_mib_s,
    })
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
