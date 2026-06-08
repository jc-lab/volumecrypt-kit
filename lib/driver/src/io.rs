//! Kernel `SectorIo` implementation backed by the lower volume device.
//!
//! Used by the JVCK store to read/write footer (and header) metadata replicas
//! on the volume during attach and progress persistence.

use alloc::string::String;

use vck_common::{SectorIo, VckResult, VolumeId};

pub struct KernelVolumeIo {
    device_path: String,
    sector_size: u32,
    total_sectors: u64,
    // TODO(driver): cache the lower PDEVICE_OBJECT / FILE_OBJECT for raw IRPs.
}

impl KernelVolumeIo {
    /// Open raw sector access to the volume identified by `volume_id`.
    pub fn open(volume_id: &VolumeId, sector_size: u32, total_sectors: u64) -> VckResult<Self> {
        // TODO(driver): resolve device_path to a device object for raw I/O.
        Ok(Self {
            device_path: volume_id.device_path.clone(),
            sector_size,
            total_sectors,
        })
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
        let _ = (lba, buf, &self.device_path);
        todo!("issue synchronous IRP_MJ_READ to the lower device")
    }

    fn write_sectors(&self, lba: u64, buf: &[u8]) -> VckResult<()> {
        let _ = (lba, buf);
        todo!("issue synchronous IRP_MJ_WRITE to the lower device")
    }
}
