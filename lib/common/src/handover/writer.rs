// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

use alloc::{vec, vec::Vec};

use crate::{handover::payload::HandoverPayload, VckError, VckResult};

pub const ACPI_DESCRIPTION_HEADER_SIZE: usize = 36;
pub const ACPI_HANDOVER_FIXED_SIZE: usize = ACPI_DESCRIPTION_HEADER_SIZE + 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcpiHandoverWriter {
    pub signature: [u8; 4],
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub physical_address: u64,
}

impl AcpiHandoverWriter {
    pub fn new<P: HandoverPayload>() -> Self {
        Self {
            signature: P::ACPI_SIGNATURE,
            oem_id: P::ACPI_OEM_ID,
            oem_table_id: *b"VCKHANDO",
            physical_address: 0,
        }
    }

    pub fn with_physical_address(mut self, physical_address: u64) -> Self {
        self.physical_address = physical_address;
        self
    }

    pub fn encode<P: HandoverPayload>(&self, payload: &P) -> VckResult<Vec<u8>> {
        let payload_bytes = crate::handover::payload::encode_payload(payload)?;
        let total_len = ACPI_HANDOVER_FIXED_SIZE
            .checked_add(payload_bytes.len())
            .ok_or(VckError::ValidationFailed("ACPI handover table too large"))?;
        let total_len_u32 = u32::try_from(total_len)
            .map_err(|_| VckError::ValidationFailed("ACPI handover table too large"))?;

        let mut table = vec![0u8; total_len];
        table[0..4].copy_from_slice(&self.signature);
        table[4..8].copy_from_slice(&total_len_u32.to_le_bytes());
        table[8] = 1;
        table[9] = 0;
        table[10..16].copy_from_slice(&self.oem_id);
        table[16..24].copy_from_slice(&self.oem_table_id);
        table[24..28].copy_from_slice(&1u32.to_le_bytes());
        table[28..32].copy_from_slice(&0x5643_4B57u32.to_le_bytes());
        table[32..36].copy_from_slice(&1u32.to_le_bytes());

        table[36..44].copy_from_slice(&self.physical_address.to_le_bytes());
        table[44..48].copy_from_slice(&(payload_bytes.len() as u32).to_le_bytes());
        table[48..52].copy_from_slice(&0u32.to_le_bytes());
        table[52..].copy_from_slice(&payload_bytes);

        let checksum = acpi_checksum(&table);
        table[9] = checksum;
        Ok(table)
    }

    /// Install the handover table so the OS sees it as a real ACPI table.
    ///
    /// A UEFI *configuration table* (`install_configuration_table`) is NOT
    /// enough: Windows exposes ACPI tables (via
    /// `ZwQuerySystemInformation(SystemFirmwareTableInformation, "ACPI", ...)`,
    /// which the driver's `read_handover` uses) only from the RSDT/XSDT. So we
    /// **inject** the table into the XSDT:
    ///
    ///   1. find the ACPI 2.0 RSDP via the UEFI config table,
    ///   2. allocate the encoded table in `ACPI_RECLAIM` memory,
    ///   3. clone the XSDT into a larger `ACPI_RECLAIM` buffer with one extra
    ///      trailing 64-bit entry pointing at our table, fix its length+checksum,
    ///   4. repoint `RSDP.XsdtAddress` at the new XSDT and fix both RSDP checksums.
    ///
    /// All ACPI integers are accessed unaligned (XSDT entries are not naturally
    /// aligned), so reads/writes go through fixed-size byte buffers.
    ///
    /// SECURITY: the table holds the plaintext VMK. The driver copies it into
    /// protected memory and zeroizes the ACPI buffer immediately after boot.
    #[cfg(feature = "uefi")]
    pub fn install_uefi<P: HandoverPayload>(&self, payload: &P) -> VckResult<()> {
        use alloc::format;
        use core::ptr::copy_nonoverlapping;
        use uefi::boot::{allocate_pages, AllocateType, MemoryType};
        use uefi::system::with_config_table;
        use uefi::table::cfg::ConfigTableEntry;

        let table = self.encode(payload)?;

        // (1) Locate the ACPI 2.0 RSDP physical address.
        let rsdp_addr = with_config_table(|entries| {
            entries
                .iter()
                .find(|e| e.guid == ConfigTableEntry::ACPI2_GUID)
                .map(|e| e.address as u64)
        })
        .ok_or(VckError::NotFound("ACPI 2.0 RSDP not present"))?;
        if rsdp_addr == 0 {
            return Err(VckError::NotFound("ACPI 2.0 RSDP address is null"));
        }

        // Allocate `len` bytes in ACPI reclaim memory (page-granular). UEFI boot
        // memory is identity-mapped, so the returned pointer is also the physical
        // address recorded in ACPI structures.
        fn alloc_acpi(len: usize) -> VckResult<*mut u8> {
            let pages = len.div_ceil(4096).max(1);
            allocate_pages(AllocateType::AnyPages, MemoryType::ACPI_RECLAIM, pages)
                .map(|p| p.as_ptr())
                .map_err(|e| VckError::Io(format!("allocate_pages(ACPI) failed: {e:?}")))
        }

        unsafe {
            let rsdp = rsdp_addr as *mut u8;
            // RSDP: xsdt_address is a u64 at offset 24; total length is a u32 at
            // offset 20; checksum byte at 8 (first 20 bytes); extended checksum
            // byte at 32 (whole `length`).
            let xsdt_addr = read_u64_unaligned(rsdp.add(24));
            if xsdt_addr == 0 {
                return Err(VckError::NotFound("RSDP has no XSDT"));
            }
            let xsdt = xsdt_addr as *mut u8;
            let xsdt_len = read_u32_unaligned(xsdt.add(4)) as usize;
            if xsdt_len < ACPI_DESCRIPTION_HEADER_SIZE {
                return Err(VckError::InvalidData("XSDT length too small"));
            }

            // (2) Place our table in ACPI reclaim memory.
            let vck = alloc_acpi(table.len())?;
            copy_nonoverlapping(table.as_ptr(), vck, table.len());

            // (3) Clone XSDT with one extra trailing 64-bit entry.
            let new_len = xsdt_len + 8;
            let new_xsdt = alloc_acpi(new_len)?;
            copy_nonoverlapping(xsdt, new_xsdt, xsdt_len);
            write_u64_unaligned(new_xsdt.add(xsdt_len), vck as u64);
            write_u32_unaligned(new_xsdt.add(4), new_len as u32);
            *new_xsdt.add(9) = 0; // zero checksum byte before recomputing
            let csum = acpi_checksum(core::slice::from_raw_parts(new_xsdt, new_len));
            *new_xsdt.add(9) = csum;

            // (4) Repoint RSDP at the new XSDT and fix both checksums.
            write_u64_unaligned(rsdp.add(24), new_xsdt as u64);
            *rsdp.add(8) = 0;
            let c1 = acpi_checksum(core::slice::from_raw_parts(rsdp, 20));
            *rsdp.add(8) = c1;
            let rsdp_len = read_u32_unaligned(rsdp.add(20)) as usize;
            if rsdp_len >= 33 {
                *rsdp.add(32) = 0;
                let c2 = acpi_checksum(core::slice::from_raw_parts(rsdp, rsdp_len));
                *rsdp.add(32) = c2;
            }
        }
        Ok(())
    }
}

pub fn acpi_checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |acc, byte| acc.wrapping_add(*byte));
    0u8.wrapping_sub(sum)
}

#[cfg(feature = "uefi")]
#[inline]
unsafe fn read_u32_unaligned(p: *const u8) -> u32 {
    let mut b = [0u8; 4];
    core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 4);
    u32::from_le_bytes(b)
}

#[cfg(feature = "uefi")]
#[inline]
unsafe fn read_u64_unaligned(p: *const u8) -> u64 {
    let mut b = [0u8; 8];
    core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 8);
    u64::from_le_bytes(b)
}

#[cfg(feature = "uefi")]
#[inline]
unsafe fn write_u32_unaligned(p: *mut u8, v: u32) {
    core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), p, 4);
}

#[cfg(feature = "uefi")]
#[inline]
unsafe fn write_u64_unaligned(p: *mut u8, v: u64) {
    core::ptr::copy_nonoverlapping(v.to_le_bytes().as_ptr(), p, 8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handover::reader::AcpiHandoverReader;
    use alloc::{vec, vec::Vec};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestPayload {
        partition_guid: [u8; 16],
        vmk: Vec<u8>,
    }

    impl HandoverPayload for TestPayload {
        const ACPI_SIGNATURE: [u8; 4] = *b"VCKD";
        const ACPI_OEM_ID: [u8; 6] = *b"SAMPLE";
    }

    fn sample() -> TestPayload {
        TestPayload {
            partition_guid: [
                0x5a, 0x95, 0x77, 0x0f, 0x3e, 0xf6, 0x11, 0xf1,
                0x8b, 0x5c, 0xb4, 0x2e, 0x99, 0x11, 0x84, 0x0a,
            ],
            vmk: (0u8..32).collect(),
        }
    }

    #[test]
    fn encode_produces_valid_acpi_header_and_zero_checksum() {
        let table = AcpiHandoverWriter::new::<TestPayload>()
            .encode(&sample())
            .expect("encode");
        assert_eq!(&table[0..4], b"VCKD");
        assert_eq!(&table[10..16], b"SAMPLE");
        // The ACPI checksum byte makes the whole-table sum zero.
        let sum = table.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
        assert_eq!(sum, 0);
        // Reported length matches the buffer length.
        let len = u32::from_le_bytes(table[4..8].try_into().unwrap()) as usize;
        assert_eq!(len, table.len());
    }

    #[test]
    fn round_trip_decode_recovers_payload() {
        let original = sample();
        let table = AcpiHandoverWriter::new::<TestPayload>()
            .encode(&original)
            .expect("encode");
        let decoded: TestPayload = AcpiHandoverReader::decode(&table).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn find_and_decode_locates_table_in_a_larger_region() {
        let table = AcpiHandoverWriter::new::<TestPayload>()
            .encode(&sample())
            .expect("encode");
        // Embed the table after some unrelated leading bytes.
        let mut region = vec![0xABu8; 64];
        region.extend_from_slice(&table);
        region.extend_from_slice(&[0xCDu8; 16]);
        let decoded: TestPayload = AcpiHandoverReader::find_and_decode(&region).expect("find");
        assert_eq!(decoded, sample());
    }

    #[test]
    fn decode_rejects_corrupted_checksum() {
        let mut table = AcpiHandoverWriter::new::<TestPayload>()
            .encode(&sample())
            .expect("encode");
        let last = table.len() - 1;
        table[last] ^= 0xFF; // corrupt payload tail → checksum no longer zero
        assert!(AcpiHandoverReader::decode::<TestPayload>(&table).is_err());
    }
}
