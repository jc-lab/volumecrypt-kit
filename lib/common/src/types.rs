use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Volume / partition GUID. Stored as a 16-byte UUID.
///
/// NOTE: GPT partition GUIDs and UEFI `EFI_GUID` use a mixed-endian layout for
/// the first three fields. Conversions to/from `uefi::Guid` must account for
/// this; see TODO in the loader/driver glue.
pub type Guid = uuid::Uuid;

/// Progressive-encryption progress state.
///
/// All sector numbers are **relative to the data region** (`offset_sector`):
/// `0` is the first encryptable sector and header/footer metadata regions are
/// not counted. The filter maps an absolute LBA to `rel = lba - offset_sector`
/// before comparing against these values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedOffset {
    /// Sectors before this (data-region relative) are already encrypted.
    pub sector: u64,
    /// Total number of sectors to encrypt (metadata regions excluded).
    pub total_sectors: u64,
}

impl EncryptedOffset {
    /// `sector` is a data-region relative sector number.
    pub fn is_encrypted(&self, sector: u64) -> bool {
        sector < self.sector
    }

    pub fn is_fully_encrypted(&self) -> bool {
        self.sector >= self.total_sectors
    }
}

/// A contiguous run of sectors `[start, start + count)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectorRange {
    pub start: u64,
    pub count: u64,
}

impl SectorRange {
    pub fn end(&self) -> u64 {
        self.start + self.count
    }

    pub fn contains(&self, sector: u64) -> bool {
        sector >= self.start && sector < self.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_offset_boundaries() {
        let off = EncryptedOffset {
            sector: 10,
            total_sectors: 100,
        };
        assert!(off.is_encrypted(9));
        assert!(!off.is_encrypted(10));
        assert!(!off.is_fully_encrypted());

        let done = EncryptedOffset {
            sector: 100,
            total_sectors: 100,
        };
        assert!(done.is_fully_encrypted());
    }

    #[test]
    fn sector_range_contains() {
        let r = SectorRange { start: 5, count: 3 };
        assert_eq!(r.end(), 8);
        assert!(r.contains(5));
        assert!(r.contains(7));
        assert!(!r.contains(8));
        assert!(!r.contains(4));
    }
}

/// Identifies an attached volume and how to reach its raw sectors.
#[derive(Debug, Clone)]
pub struct VolumeId {
    /// GPT partition unique GUID (matched against the handover `partition_guid`).
    pub partition_guid: Guid,
    /// NT device path, e.g. `\Device\HarddiskVolume3`. Used for raw footer
    /// metadata read/write by the kernel `SectorIo` implementation.
    pub device_path: String,
}
