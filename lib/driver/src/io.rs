//! Kernel `SectorIo` implementation backed by a volume device object.
//!
//! Used by the JVCK store to read/write footer (and header) metadata replicas
//! and by the progressive-encryption sweep. All I/O is issued synchronously at
//! PASSIVE_LEVEL via `IoBuildSynchronousFsdRequest` + `IofCallDriver`.
//!
//! Two construction modes:
//! - [`KernelVolumeIo::open`]: resolve an NT device path (e.g. `\??\D:`) to its
//!   device/file object via `IoGetDeviceObjectPointer` (holds a reference).
//! - [`KernelVolumeIo::from_lower_device`]: wrap the lower device a filter is
//!   attached above, so the sweep reads plaintext / writes ciphertext without
//!   re-entering our own filter.

use core::ffi::c_void;
use core::ptr::null_mut;

use vck_common::{SectorIo, VckError, VckResult, VolumeId};
use wdk_sys::{
    ntddk::{
        IoBuildDeviceIoControlRequest, IoBuildSynchronousFsdRequest, IoGetDeviceObjectPointer,
        IofCallDriver, KeInitializeEvent, KeWaitForSingleObject, ObfDereferenceObject,
    },
    FILE_READ_DATA, FILE_WRITE_DATA, IO_STATUS_BLOCK, IRP_MJ_READ, IRP_MJ_WRITE, KEVENT,
    LARGE_INTEGER, PDEVICE_OBJECT, PFILE_OBJECT, PIRP, _EVENT_TYPE::NotificationEvent,
    _KWAIT_REASON::Executive, _MODE::KernelMode,
};

use crate::nt::{nt_success, UnicodeString, STATUS_PENDING};

/// Set the FileObject in the IRP's next stack location (the one the target
/// driver will see). Volume/disk devices opened via `IoGetDeviceObjectPointer`
/// dereference the FileObject for raw reads/writes/IOCTLs; a NULL one bugchecks.
unsafe fn set_next_file_object(irp: PIRP, file_object: PFILE_OBJECT) {
    if file_object.is_null() {
        return;
    }
    let next = (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation
        .offset(-1);
    (*next).FileObject = file_object;
}

// METHOD_BUFFERED disk IOCTLs (CTL_CODE values are stable across SDKs).
const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x0007_0000;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
// Offset of BytesPerSector within DISK_GEOMETRY.
const DISK_GEOMETRY_BYTES_PER_SECTOR_OFFSET: usize = 20;

pub struct KernelVolumeIo {
    device_object: PDEVICE_OBJECT,
    /// Non-null only when we own a reference obtained from
    /// `IoGetDeviceObjectPointer` (released on drop).
    file_object: PFILE_OBJECT,
    sector_size: u32,
    total_sectors: u64,
}

// The device/file object pointers are used only under driver-side serialization
// (registry/engine locks); the kernel owns their lifetime.
unsafe impl Send for KernelVolumeIo {}
unsafe impl Sync for KernelVolumeIo {}

impl KernelVolumeIo {
    /// Resolve `volume_id.device_path` (an NT path such as `\??\D:` or
    /// `\Device\HarddiskVolume3`) and hold a reference to its device object.
    pub fn open(volume_id: &VolumeId, sector_size: u32, total_sectors: u64) -> VckResult<Self> {
        let name = UnicodeString::from_str(&volume_id.device_path);
        let mut device_object: PDEVICE_OBJECT = null_mut();
        let mut file_object: PFILE_OBJECT = null_mut();

        let status = unsafe {
            IoGetDeviceObjectPointer(
                name.as_ptr(),
                FILE_READ_DATA | FILE_WRITE_DATA,
                &mut file_object,
                &mut device_object,
            )
        };
        crate::driver_println!(
            "KVIO: IoGetDeviceObjectPointer status=0x{:08x} stack={}",
            status,
            crate::debug::remaining_stack()
        );
        if !nt_success(status) {
            return Err(VckError::Io("IoGetDeviceObjectPointer failed".into()));
        }

        Ok(Self {
            device_object,
            file_object,
            sector_size,
            total_sectors,
        })
    }

    /// Resolve `volume_id.device_path` and query the volume geometry
    /// (`sector_size`, `total_sectors`) via disk IOCTLs.
    pub fn open_query(volume_id: &VolumeId) -> VckResult<Self> {
        let mut me = Self::open(volume_id, 0, 0)?;
        me.query_geometry()?;
        Ok(me)
    }

    fn query_geometry(&mut self) -> VckResult<()> {
        // DISK_GEOMETRY is 24 bytes; over-allocate a little for safety.
        let mut geom = [0u8; 32];
        crate::driver_println!("KVIO: ioctl DRIVE_GEOMETRY");
        self.device_ioctl(IOCTL_DISK_GET_DRIVE_GEOMETRY, &mut geom)?;
        let bps_off = DISK_GEOMETRY_BYTES_PER_SECTOR_OFFSET;
        let bytes_per_sector =
            u32::from_le_bytes(geom[bps_off..bps_off + 4].try_into().unwrap());
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
        let mut event: KEVENT = unsafe { core::mem::zeroed() };
        let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };

        unsafe {
            KeInitializeEvent(&mut event, NotificationEvent, 0);
        }

        crate::driver_println!("KVIO: IoBuildDeviceIoControlRequest");
        let irp = unsafe {
            IoBuildDeviceIoControlRequest(
                code,
                self.device_object,
                null_mut(),
                0,
                output.as_mut_ptr().cast::<c_void>(),
                output.len() as u32,
                0, // InternalDeviceIoControl = FALSE
                &mut event,
                &mut iosb,
            )
        };
        crate::driver_println!("KVIO: irp_built={}", (!irp.is_null()) as u32);
        if irp.is_null() {
            return Err(VckError::Io("IoBuildDeviceIoControlRequest failed".into()));
        }
        unsafe { set_next_file_object(irp, self.file_object) };

        crate::driver_println!("KVIO: IofCallDriver (dev ioctl)");
        let mut status = unsafe { IofCallDriver(self.device_object, irp) };
        crate::driver_println!("KVIO: IofCallDriver returned 0x{:08x}", status);
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
            crate::driver_println!("KVIO: waited iosb=0x{:08x}", status);
        }
        if !nt_success(status) {
            return Err(VckError::Io("volume geometry IOCTL failed".into()));
        }
        Ok(())
    }

    /// Wrap an existing lower device object (filter's attach target). Does not
    /// take a reference; the caller guarantees the device outlives this value.
    pub fn from_lower_device(
        device_object: PDEVICE_OBJECT,
        sector_size: u32,
        total_sectors: u64,
    ) -> Self {
        Self {
            device_object,
            file_object: null_mut(),
            sector_size,
            total_sectors,
        }
    }

    /// Issue one synchronous read/write IRP covering `len` bytes at `lba`.
    fn run_sync(&self, major: u32, lba: u64, buf: *mut u8, len: usize) -> VckResult<()> {
        if len == 0 {
            return Ok(());
        }
        crate::driver_println!(
            "KVIO: run_sync major={} lba={} len={} stack={}",
            major,
            lba,
            len,
            crate::debug::remaining_stack()
        );
        let byte_offset = lba
            .checked_mul(self.sector_size as u64)
            .ok_or_else(|| VckError::Io("sector offset overflow".into()))?;
        let length =
            u32::try_from(len).map_err(|_| VckError::Io("I/O length too large".into()))?;

        let mut event: KEVENT = unsafe { core::mem::zeroed() };
        let mut iosb: IO_STATUS_BLOCK = unsafe { core::mem::zeroed() };
        let mut offset = LARGE_INTEGER {
            QuadPart: byte_offset as i64,
        };

        unsafe {
            // BOOLEAN State = FALSE (0).
            KeInitializeEvent(&mut event, NotificationEvent, 0);
        }

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
            return Err(VckError::Io("IoBuildSynchronousFsdRequest failed".into()));
        }
        unsafe { set_next_file_object(irp, self.file_object) };

        let mut status = unsafe { IofCallDriver(self.device_object, irp) };
        if status == STATUS_PENDING {
            unsafe {
                // Wait at PASSIVE_LEVEL until the lower driver completes the IRP.
                let _ = KeWaitForSingleObject(
                    (&mut event as *mut KEVENT).cast::<c_void>(),
                    Executive,
                    KernelMode as i8,
                    0, // Alertable = FALSE
                    null_mut(),
                );
                status = iosb.__bindgen_anon_1.Status;
            }
        }

        crate::driver_println!("KVIO: run_sync done status=0x{:08x}", status);
        if !nt_success(status) {
            return Err(VckError::Io("volume I/O IRP failed".into()));
        }
        Ok(())
    }
}

impl Drop for KernelVolumeIo {
    fn drop(&mut self) {
        if !self.file_object.is_null() {
            unsafe {
                ObfDereferenceObject(self.file_object.cast::<c_void>());
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
        self.run_sync(IRP_MJ_READ, lba, buf.as_mut_ptr(), buf.len())
    }

    fn write_sectors(&self, lba: u64, buf: &[u8]) -> VckResult<()> {
        // The write path only reads from this buffer; the cast to `*mut` is for
        // the C signature and the bytes are not modified.
        self.run_sync(IRP_MJ_WRITE, lba, buf.as_ptr() as *mut u8, buf.len())
    }
}
