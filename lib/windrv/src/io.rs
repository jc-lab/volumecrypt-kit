// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Kernel `SectorIo` implementation backed by a volume file handle.
//!
//! Used by the JVCK store to read/write footer (and header) metadata replicas
//! and by the progressive-encryption sweep.
//!
//! The volume is opened with `ZwCreateFile` (synchronous, kernel handle) and,
//! crucially, `FSCTL_ALLOW_EXTENDED_DASD_IO` is issued via `ZwFsControlFile` so
//! reads/writes can reach the partition tail beyond the (shrunk) filesystem
//! extent — that tail is where the JVCK footer metadata lives. All I/O is
//! synchronous at PASSIVE_LEVEL (`FILE_SYNCHRONOUS_IO_NONALERT`), so no IRP
//! plumbing or completion events are needed.

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::null_mut;

use vck_common::{SectorIo, VckError, VckResult, VolumeId};
use wdk_sys::{
    ntddk::{
        ObOpenObjectByPointer, ZwClose, ZwCreateFile, ZwDeviceIoControlFile, ZwFsControlFile,
        ZwReadFile, ZwWriteFile,
    },
    FILE_READ_DATA, FILE_WRITE_DATA, HANDLE, IO_STATUS_BLOCK, LARGE_INTEGER, OBJECT_ATTRIBUTES,
    PDEVICE_OBJECT,
};

use crate::nt::{nt_success, UnicodeString};

// METHOD_BUFFERED disk IOCTLs (CTL_CODE values are stable across SDKs).
const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x0007_0000;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
// IOCTL_DISK_GET_PARTITION_INFO_EX: CTL_CODE(FILE_DEVICE_DISK=7, 0x12,
// METHOD_BUFFERED, FILE_ANY_ACCESS).
const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048;
// FSCTL_ALLOW_EXTENDED_DASD_IO: CTL_CODE(FILE_DEVICE_FILE_SYSTEM=9, 32,
// METHOD_NEITHER=3, FILE_ANY_ACCESS=0) = (9<<16) | (32<<2) | 3.
const FSCTL_ALLOW_EXTENDED_DASD_IO: u32 = 0x0009_0083;
// Offset of BytesPerSector within DISK_GEOMETRY.
const DISK_GEOMETRY_BYTES_PER_SECTOR_OFFSET: usize = 20;

// ZwCreateFile / OBJECT_ATTRIBUTES constants (stable NT ABI values; not all are
// re-exported by the bindings, so they are spelled out here).
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
// Bypass the file system cache so ZwReadFile/ZwWriteFile go directly to the
// underlying device. Critical for raw sector I/O on a mounted NTFS volume:
// without this NTFS may serve reads from its internal cache (wrong data).
const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const OBJ_KERNEL_HANDLE: u32 = 0x0000_0200;

pub struct KernelVolumeIo {
    handle: HANDLE,
    sector_size: u32,
    total_sectors: u64,
}

// The handle is a kernel handle (`OBJ_KERNEL_HANDLE`), valid in any thread
// context; access is serialized by the driver-side registry/engine locks.
unsafe impl Send for KernelVolumeIo {}
unsafe impl Sync for KernelVolumeIo {}

impl KernelVolumeIo {
    /// Open `volume_id.device_path` (an NT path such as `\??\D:`) for raw
    /// synchronous I/O and enable extended-DASD access on the handle.
    pub fn open(volume_id: &VolumeId, sector_size: u32, total_sectors: u64) -> VckResult<Self> {
        let name = UnicodeString::from_str(&volume_id.device_path);

        let mut oa: OBJECT_ATTRIBUTES = unsafe { core::mem::zeroed() };
        oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        oa.ObjectName = name.as_ptr();
        oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;

        let mut handle: HANDLE = null_mut();
        let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        let status = unsafe {
            ZwCreateFile(
                &mut handle,
                FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                &mut oa,
                &mut iosb,
                null_mut(),
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING,
                null_mut(),
                0,
            )
        };
        crate::driver_println!(
            "KVIO: ZwCreateFile status=0x{:08x} stack={}",
            status,
            crate::debug::remaining_stack()
        );
        if !nt_success(status) {
            return Err(VckError::Io("ZwCreateFile failed".into()));
        }

        let me = Self {
            handle,
            sector_size,
            total_sectors,
        };
        // Lift the filesystem-extent bound so the shrunk-away tail (footer
        // metadata) is reachable. Best-effort: a raw partition device does not
        // need it, so failures are only logged.
        me.allow_extended_dasd_io();
        Ok(me)
    }

    /// Open `volume_id.device_path` and query the volume geometry
    /// (`sector_size`, `total_sectors`) via disk IOCTLs.
    pub fn open_query(volume_id: &VolumeId) -> VckResult<Self> {
        let mut me = Self::open(volume_id, 0, 0)?;
        me.query_geometry()?;
        Ok(me)
    }

    /// Wrap an existing kernel handle (e.g. one already opened for lock/dismount)
    /// as a KernelVolumeIo, querying geometry from it. The handle ownership is
    /// transferred — `Drop` will call `ZwClose` on it.
    pub fn from_handle_query(handle: wdk_sys::HANDLE) -> VckResult<Self> {
        let mut me = Self { handle, sector_size: 0, total_sectors: 0 };
        me.allow_extended_dasd_io();
        me.query_geometry()?;
        Ok(me)
    }

    /// Open a kernel handle directly to a device object (e.g. the lower device
    /// below the filter) without going through the symbolic-link / object-manager
    /// path. `ObOpenObjectByPointer` yields a handle that routes I/O to exactly
    /// that device object — it bypasses any filter sitting above it.
    ///
    /// Used to create `sweep_io` so the background encryption sweep never
    /// re-enters our own filter.
    pub fn from_device_object(
        device_object: PDEVICE_OBJECT,
        sector_size: u32,
        total_sectors: u64,
    ) -> VckResult<Self> {
        let mut handle: HANDLE = null_mut();
        let status = unsafe {
            ObOpenObjectByPointer(
                device_object.cast::<c_void>(),
                OBJ_KERNEL_HANDLE,
                null_mut(),         // PassedAccessState
                FILE_READ_DATA | FILE_WRITE_DATA,
                null_mut(),         // ObjectType — null = any
                0,                  // KernelMode
                &mut handle,
            )
        };
        crate::driver_println!("KVIO: from_device_object status=0x{:08x}", status);
        if !nt_success(status) {
            return Err(VckError::Io("ObOpenObjectByPointer(lower) failed".into()));
        }
        // FSCTL_ALLOW_EXTENDED_DASD_IO is sent to the file system above the
        // device. For the raw lower device we don't need it (the lower device
        // has no FS extent check), so we skip it.
        Ok(Self {
            handle,
            sector_size,
            total_sectors,
        })
    }

    /// Open a kernel handle directly to `device_object` (bypassing any filter
    /// above it) and query its geometry. Combines [`Self::from_device_object`]
    /// with a geometry probe — used by the boot handover path to learn the raw
    /// lower-device sector size / capacity before reading footer metadata.
    pub fn from_device_object_query(device_object: PDEVICE_OBJECT) -> VckResult<Self> {
        let mut me = Self::from_device_object(device_object, 0, 0)?;
        me.query_geometry()?;
        Ok(me)
    }

    /// Read the GPT unique partition GUID (`PARTITION_INFORMATION_GPT.PartitionId`)
    /// of the underlying device via `IOCTL_DISK_GET_PARTITION_INFO_EX`.
    ///
    /// Returns `NotFound` if the device is not GPT-partitioned. The 16 raw GUID
    /// bytes (at offset 48 of `PARTITION_INFORMATION_EX`, Microsoft mixed-endian
    /// layout) are converted with [`vck_common::types::guid_from_windows_bytes`]
    /// so the result matches the canonical GUID the loader carries in the
    /// handover.
    pub fn read_gpt_partition_id(&self) -> VckResult<vck_common::types::Guid> {
        // PARTITION_INFORMATION_EX (x64) layout:
        //   0  PartitionStyle (4) + pad (4)
        //   8  StartingOffset (8)
        //   16 PartitionLength (8)
        //   24 PartitionNumber (4) + RewritePartition/IsServicePartition + pad
        //   32 union { GPT { PartitionType[16], PartitionId[16], ... } }
        // PartitionStyle: 0=MBR, 1=GPT, 2=RAW.
        const PARTITION_STYLE_GPT: u32 = 1;
        const GPT_PARTITION_ID_OFFSET: usize = 48;
        let mut buf = [0u8; 144];
        self.device_ioctl(IOCTL_DISK_GET_PARTITION_INFO_EX, &mut buf)?;
        let style = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if style != PARTITION_STYLE_GPT {
            return Err(VckError::NotFound("device is not GPT-partitioned"));
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&buf[GPT_PARTITION_ID_OFFSET..GPT_PARTITION_ID_OFFSET + 16]);
        Ok(vck_common::types::guid_from_windows_bytes(id))
    }

    fn allow_extended_dasd_io(&self) {
        let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        let status = unsafe {
            ZwFsControlFile(
                self.handle,
                null_mut(),
                None,
                null_mut(),
                &mut iosb,
                FSCTL_ALLOW_EXTENDED_DASD_IO,
                null_mut(),
                0,
                null_mut(),
                0,
            )
        };
        crate::driver_println!("KVIO: allow_extended_dasd_io status=0x{:08x}", status);
    }

    fn query_geometry(&mut self) -> VckResult<()> {
        // DISK_GEOMETRY is 24 bytes; over-allocate a little for safety.
        let mut geom = [0u8; 32];
        crate::driver_println!("KVIO: ioctl DRIVE_GEOMETRY");
        self.device_ioctl(IOCTL_DISK_GET_DRIVE_GEOMETRY, &mut geom)?;
        let bps_off = DISK_GEOMETRY_BYTES_PER_SECTOR_OFFSET;
        let bytes_per_sector = u32::from_le_bytes(geom[bps_off..bps_off + 4].try_into().unwrap());
        if bytes_per_sector == 0 {
            return Err(VckError::Io("volume reported zero sector size".into()));
        }

        // GET_LENGTH_INFORMATION { LARGE_INTEGER Length } -> 8 bytes.
        let mut len = [0u8; 8];
        crate::driver_println!("KVIO: ioctl LENGTH_INFO (bps={})", bytes_per_sector);
        self.device_ioctl(IOCTL_DISK_GET_LENGTH_INFO, &mut len)?;
        let total_bytes = u64::from_le_bytes(len);

        self.sector_size = bytes_per_sector;
        self.total_sectors = total_bytes / bytes_per_sector as u64;
        crate::driver_println!(
            "KVIO: geometry bps={} total_sectors={}",
            bytes_per_sector,
            self.total_sectors
        );
        Ok(())
    }

    /// Issue a synchronous METHOD_BUFFERED device IOCTL with no input buffer.
    fn device_ioctl(&self, code: u32, output: &mut [u8]) -> VckResult<()> {
        crate::driver_println!(
            "KVIO: device_ioctl code=0x{:08x} outlen={} stack={}",
            code,
            output.len(),
            crate::debug::remaining_stack()
        );
        let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        let status = unsafe {
            ZwDeviceIoControlFile(
                self.handle,
                null_mut(),
                None,
                null_mut(),
                &mut iosb,
                code,
                null_mut(),
                0,
                output.as_mut_ptr().cast::<c_void>(),
                output.len() as u32,
            )
        };
        crate::driver_println!("KVIO: device_ioctl status=0x{:08x}", status);
        if !nt_success(status) {
            return Err(VckError::Io("volume geometry IOCTL failed".into()));
        }
        Ok(())
    }

    /// Issue one synchronous read or write covering `len` bytes at `lba`.
    fn run_sync(&self, is_write: bool, lba: u64, buf: *mut u8, len: usize) -> VckResult<()> {
        if len == 0 {
            return Ok(());
        }
        crate::driver_println!(
            "KVIO: run_sync write={} lba={} len={} stack={}",
            is_write as u32,
            lba,
            len,
            crate::debug::remaining_stack()
        );
        let byte_offset = lba
            .checked_mul(self.sector_size as u64)
            .ok_or_else(|| VckError::Io("sector offset overflow".into()))?;
        let length =
            u32::try_from(len).map_err(|_| VckError::Io("I/O length too large".into()))?;

        let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        let mut offset = LARGE_INTEGER {
            QuadPart: byte_offset as i64,
        };

        let status = unsafe {
            if is_write {
                ZwWriteFile(
                    self.handle,
                    null_mut(),
                    None,
                    null_mut(),
                    &mut iosb,
                    buf.cast::<c_void>(),
                    length,
                    &mut offset,
                    null_mut(),
                )
            } else {
                ZwReadFile(
                    self.handle,
                    null_mut(),
                    None,
                    null_mut(),
                    &mut iosb,
                    buf.cast::<c_void>(),
                    length,
                    &mut offset,
                    null_mut(),
                )
            }
        };

        crate::driver_println!("KVIO: run_sync done status=0x{:08x}", status);
        if !nt_success(status) {
            return Err(VckError::Io("volume I/O failed".into()));
        }
        Ok(())
    }
}

impl Drop for KernelVolumeIo {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = ZwClose(self.handle);
            }
        }
    }
}

impl SectorIo for KernelVolumeIo {
    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn total_sectors(&self) -> u64 {
        self.total_sectors
    }

    fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> VckResult<()> {
        self.run_sync(false, lba, buf.as_mut_ptr(), buf.len())
    }

    fn write_sectors(&self, lba: u64, buf: &[u8]) -> VckResult<()> {
        // The write path only reads from this buffer; the cast to `*mut` is for
        // the C signature and the bytes are not modified.
        self.run_sync(true, lba, buf.as_ptr() as *mut u8, buf.len())
    }
}

// ---------------------------------------------------------------------------
// IRP-based sector I/O targeted at a specific device object.
//
// Used for the background encryption sweep so that its I/O goes directly to
// the volume device BELOW our filter (`lower_device` in the filter stack)
// rather than through ZwCreateFile paths that Windows re-routes to the top of
// the stack (our filter). Bypassing the filter prevents the deadlock that would
// occur when the sweep holds `encryption.lock()` during I/O that then tries to
// acquire the same lock in a filter completion routine.
// ---------------------------------------------------------------------------

use wdk_sys::{
    ntddk::{
        IoBuildDeviceIoControlRequest, IoBuildSynchronousFsdRequest, IofCallDriver,
        KeInitializeEvent, KeWaitForSingleObject,
    },
    KEVENT, IRP_MJ_READ, IRP_MJ_WRITE, _EVENT_TYPE::NotificationEvent, _KWAIT_REASON::Executive,
    _MODE::KernelMode,
};
use crate::nt::STATUS_PENDING;

/// IRP-based sector I/O routed directly to `device_object`, bypassing any
/// filter sitting above it. The caller guarantees the device outlives this
/// value (typically by holding a registry entry alive).
pub struct LowerDeviceIo {
    device_object: PDEVICE_OBJECT,
    sector_size: u32,
    total_sectors: u64,
}

unsafe impl Send for LowerDeviceIo {}
unsafe impl Sync for LowerDeviceIo {}

impl LowerDeviceIo {
    /// Wrap a lower device object. Does NOT take a reference; the caller must
    /// ensure the device outlives this value.
    pub fn new(device_object: PDEVICE_OBJECT, sector_size: u32, total_sectors: u64) -> Self {
        Self { device_object, sector_size, total_sectors }
    }

    /// Send a METHOD_BUFFERED disk IOCTL (no input) directly to the device via an
    /// IRP. Unlike a handle opened with `ObOpenObjectByPointer` (which is a device
    /// handle and rejects `ZwDeviceIoControlFile` with `OBJECT_TYPE_MISMATCH`),
    /// `IoBuildDeviceIoControlRequest` + `IofCallDriver` works against the raw
    /// lower device object.
    fn device_ioctl(&self, code: u32, out: &mut [u8]) -> VckResult<()> {
        let mut event: KEVENT = unsafe { core::mem::zeroed() };
        let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        unsafe { KeInitializeEvent(&mut event, NotificationEvent, 0) };

        let irp = unsafe {
            IoBuildDeviceIoControlRequest(
                code,
                self.device_object,
                null_mut(),
                0,
                out.as_mut_ptr().cast::<c_void>(),
                out.len() as u32,
                0, // InternalDeviceIoControl = FALSE
                &mut event,
                &mut iosb,
            )
        };
        if irp.is_null() {
            return Err(VckError::Io("IoBuildDeviceIoControlRequest(lower) failed".into()));
        }
        let mut status = unsafe { IofCallDriver(self.device_object, irp) };
        if status == STATUS_PENDING {
            unsafe {
                let _ = KeWaitForSingleObject(
                    (&mut event as *mut KEVENT).cast::<c_void>(),
                    Executive,
                    KernelMode as i8,
                    0,
                    null_mut(),
                );
                status = iosb.__bindgen_anon_1.Status;
            }
        }
        if !nt_success(status) {
            return Err(VckError::Io("lower device IOCTL failed".into()));
        }
        Ok(())
    }

    /// Query the device geometry (`sector_size`, `total_sectors`) over IRP IOCTLs
    /// and store it on `self`.
    pub fn query_geometry(&mut self) -> VckResult<()> {
        let mut geom = [0u8; 32];
        self.device_ioctl(IOCTL_DISK_GET_DRIVE_GEOMETRY, &mut geom)?;
        let off = DISK_GEOMETRY_BYTES_PER_SECTOR_OFFSET;
        let bps = u32::from_le_bytes(geom[off..off + 4].try_into().unwrap());
        if bps == 0 {
            return Err(VckError::Io("lower device reported zero sector size".into()));
        }
        let mut len = [0u8; 8];
        self.device_ioctl(IOCTL_DISK_GET_LENGTH_INFO, &mut len)?;
        let total_bytes = u64::from_le_bytes(len);
        self.sector_size = bps;
        self.total_sectors = total_bytes / bps as u64;
        Ok(())
    }

    /// Read this device's GPT unique partition GUID (`PartitionId`) over an IRP
    /// `IOCTL_DISK_GET_PARTITION_INFO_EX`. Returns `NotFound` for non-GPT devices.
    pub fn read_gpt_partition_id(&self) -> VckResult<vck_common::types::Guid> {
        const PARTITION_STYLE_GPT: u32 = 1;
        const GPT_PARTITION_ID_OFFSET: usize = 48;
        let mut buf = [0u8; 144];
        self.device_ioctl(IOCTL_DISK_GET_PARTITION_INFO_EX, &mut buf)?;
        let style = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        if style != PARTITION_STYLE_GPT {
            return Err(VckError::NotFound("device is not GPT-partitioned"));
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&buf[GPT_PARTITION_ID_OFFSET..GPT_PARTITION_ID_OFFSET + 16]);
        Ok(vck_common::types::guid_from_windows_bytes(id))
    }

    fn run_sync(&self, major: u32, lba: u64, buf: *mut u8, len: usize) -> VckResult<()> {
        if len == 0 {
            return Ok(());
        }
        let byte_offset = lba
            .checked_mul(self.sector_size as u64)
            .ok_or_else(|| VckError::Io("sector offset overflow".into()))?;
        let length = u32::try_from(len).map_err(|_| VckError::Io("I/O length too large".into()))?;

        let mut event: KEVENT = unsafe { core::mem::zeroed() };
        let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        let mut offset = LARGE_INTEGER { QuadPart: byte_offset as i64 };

        unsafe { KeInitializeEvent(&mut event, NotificationEvent, 0) };

        let irp = unsafe {
            IoBuildSynchronousFsdRequest(
                major,
                self.device_object,
                buf.cast::<c_void>(),
                length,
                &mut offset,
                &mut event,
                &mut iosb,
            )
        };
        if irp.is_null() {
            return Err(VckError::Io("IoBuildSynchronousFsdRequest(lower) failed".into()));
        }

        let mut status = unsafe { IofCallDriver(self.device_object, irp) };
        if status == STATUS_PENDING {
            unsafe {
                let _ = KeWaitForSingleObject(
                    (&mut event as *mut KEVENT).cast::<c_void>(),
                    Executive,
                    KernelMode as i8,
                    0,
                    null_mut(),
                );
                status = iosb.__bindgen_anon_1.Status;
            }
        }
        if !nt_success(status) {
            return Err(VckError::Io("lower device I/O failed".into()));
        }
        Ok(())
    }
}

impl SectorIo for LowerDeviceIo {
    fn sector_size(&self) -> u32 { self.sector_size }
    fn total_sectors(&self) -> u64 { self.total_sectors }

    fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> VckResult<()> {
        self.run_sync(IRP_MJ_READ, lba, buf.as_mut_ptr(), buf.len())
    }

    fn write_sectors(&self, lba: u64, buf: &[u8]) -> VckResult<()> {
        self.run_sync(IRP_MJ_WRITE, lba, buf.as_ptr() as *mut u8, buf.len())
    }
}

// ---------------------------------------------------------------------------
// Utility: open a synchronous kernel handle to a volume NT path and send
// no-in/no-out FSCTLs. Used by `handle_jvck_attach` for lock/dismount/unlock.
// ---------------------------------------------------------------------------

/// Open a synchronous kernel handle to `nt_path`. Returns `None` if the open
/// fails (caller decides whether that is fatal).
pub fn open_volume_handle_raw(nt_path: &str) -> Option<wdk_sys::HANDLE> {
    let name = UnicodeString::from_str(nt_path);
    let mut oa: OBJECT_ATTRIBUTES = unsafe { core::mem::zeroed() };
    oa.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
    oa.ObjectName = name.as_ptr();
    oa.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;

    let mut handle: wdk_sys::HANDLE = null_mut();
    let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
    let status = unsafe {
        ZwCreateFile(
            &mut handle,
            FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
            &mut oa,
            &mut iosb,
            null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            null_mut(),
            0,
        )
    };
    if nt_success(status) { Some(handle) } else { None }
}

/// Send a no-in/no-out FSCTL to `handle`. Returns the NTSTATUS.
/// Wraps a `SectorIo` and adds a fixed LBA offset to all reads/writes.
///
/// Used for sweep_io when targeting the raw disk device (`\Device\Harddisk0\DR0`)
/// to bypass PartMgr's per-partition write protection. The `partition_start_lba`
/// is added to every LBA so that logical partition sector 0 maps to the correct
/// physical disk sector.
pub struct OffsetSectorIo {
    inner: alloc::sync::Arc<dyn vck_common::SectorIo>,
    partition_start_lba: u64,
}

impl OffsetSectorIo {
    pub fn new(
        inner: alloc::sync::Arc<dyn vck_common::SectorIo>,
        partition_start_lba: u64,
    ) -> Self {
        Self { inner, partition_start_lba }
    }
}

impl vck_common::SectorIo for OffsetSectorIo {
    fn sector_size(&self) -> u32 { self.inner.sector_size() }
    fn total_sectors(&self) -> u64 { self.inner.total_sectors() }
    fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> VckResult<()> {
        self.inner.read_sectors(self.partition_start_lba + lba, buf)
    }
    fn write_sectors(&self, lba: u64, buf: &[u8]) -> VckResult<()> {
        self.inner.write_sectors(self.partition_start_lba + lba, buf)
    }
}

pub fn send_fsctl(handle: wdk_sys::HANDLE, code: u32) -> i32 {
    let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
    unsafe {
        ZwFsControlFile(
            handle, null_mut(), None, null_mut(), &mut iosb,
            code, null_mut(), 0, null_mut(), 0,
        )
    }
}
