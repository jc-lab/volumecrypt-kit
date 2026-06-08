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
