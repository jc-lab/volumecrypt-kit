use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Volume / partition GUID. Stored as a 16-byte UUID.
///
/// NOTE: GPT partition GUIDs and UEFI `EFI_GUID` use a mixed-endian layout for
/// the first three fields. Conversions to/from `uefi::Guid` must account for
/// this; see [`guid_from_windows_bytes`].
pub type Guid = uuid::Uuid;

/// Build a [`Guid`] from the 16 raw bytes of a Windows `GUID` / GPT
/// `PARTITION_INFORMATION_GPT.PartitionId` / `EFI_GUID` as they appear in
/// memory.
///
/// Those structures store the first three fields (`Data1: u32`, `Data2: u16`,
/// `Data3: u16`) little-endian and the trailing 8 bytes (`Data4`) as-is. The
/// `uuid` crate's canonical (RFC 4122) byte order is big-endian for those
/// fields, so the raw bytes must be read with `from_bytes_le` for the resulting
/// `Guid` to match the canonical string the Go app writes into `vck.json`
/// (which formats `Data1`/`Data2`/`Data3` as integers).
pub fn guid_from_windows_bytes(bytes: [u8; 16]) -> Guid {
    Guid::from_bytes_le(bytes)
}

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
    fn guid_from_windows_bytes_matches_canonical() {
        // Windows GUID in-memory bytes for {12345678-9abc-def0-1122-334455667788}:
        // Data1=0x12345678 LE, Data2=0x9abc LE, Data3=0xdef0 LE, Data4 as-is.
        let win = [
            0x78, 0x56, 0x34, 0x12, // Data1 LE
            0xbc, 0x9a, // Data2 LE
            0xf0, 0xde, // Data3 LE
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // Data4
        ];
        let guid = guid_from_windows_bytes(win);
        let canonical = uuid::Uuid::parse_str("12345678-9abc-def0-1122-334455667788").unwrap();
        assert_eq!(guid, canonical);
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
