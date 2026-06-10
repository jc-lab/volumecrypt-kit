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

    #[cfg(feature = "uefi")]
    pub fn install_uefi<P: HandoverPayload>(
        &self,
        payload: &P,
        table_guid: &'static uefi::Guid,
    ) -> VckResult<()> {
        #[allow(unused_imports)]
        use alloc::format;
        use core::ptr::copy_nonoverlapping;
        use uefi::boot::{allocate_pool, install_configuration_table, MemoryType};

        let table = self.encode(payload)?;
        let ptr = allocate_pool(MemoryType::RUNTIME_SERVICES_DATA, table.len())
            .map_err(|err| VckError::Io(format!("uefi allocate_pool failed: {err:?}")))?;
        unsafe {
            copy_nonoverlapping(table.as_ptr(), ptr.as_ptr(), table.len());
            install_configuration_table(table_guid, ptr.as_ptr().cast()).map_err(|err| {
                VckError::Io(format!("uefi install_configuration_table failed: {err:?}"))
            })?;
        }
        Ok(())
    }
}

pub fn acpi_checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |acc, byte| acc.wrapping_add(*byte));
    0u8.wrapping_sub(sum)
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
