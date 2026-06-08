use crate::{
    handover::{payload::HandoverPayload, writer::ACPI_HANDOVER_FIXED_SIZE},
    VckError, VckResult,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct AcpiHandoverReader;

impl AcpiHandoverReader {
    pub fn decode<P: HandoverPayload>(bytes: &[u8]) -> VckResult<P> {
        let payload_bytes = Self::extract_payload(bytes, P::ACPI_SIGNATURE, P::ACPI_OEM_ID)?;
        crate::handover::payload::decode_payload(payload_bytes)
    }

    pub fn find_and_decode<P: HandoverPayload>(tables: &[u8]) -> VckResult<P> {
        let bytes = Self::find_table(tables, P::ACPI_SIGNATURE)?;
        Self::decode::<P>(bytes)
    }

    pub fn find_table<'a>(tables: &'a [u8], signature: [u8; 4]) -> VckResult<&'a [u8]> {
        let mut cursor = 0usize;
        while cursor + 8 <= tables.len() {
            if tables[cursor..cursor + 4] == signature {
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&tables[cursor + 4..cursor + 8]);
                let length = u32::from_le_bytes(len_bytes) as usize;
                if length < ACPI_HANDOVER_FIXED_SIZE || cursor + length > tables.len() {
                    return Err(VckError::ValidationFailed("invalid ACPI table length"));
                }
                return Ok(&tables[cursor..cursor + length]);
            }
            cursor += 1;
        }
        Err(VckError::NotFound("ACPI handover table not found"))
    }

    fn extract_payload<'a>(
        table: &'a [u8],
        signature: [u8; 4],
        oem_id: [u8; 6],
    ) -> VckResult<&'a [u8]> {
        if table.len() < ACPI_HANDOVER_FIXED_SIZE {
            return Err(VckError::SizeMismatch {
                expected: ACPI_HANDOVER_FIXED_SIZE,
                actual: table.len(),
            });
        }
        if table[0..4] != signature {
            return Err(VckError::SignatureMismatch);
        }
        if table[10..16] != oem_id {
            return Err(VckError::ValidationFailed("ACPI OEM ID mismatch"));
        }
        let checksum = table.iter().fold(0u8, |acc, byte| acc.wrapping_add(*byte));
        if checksum != 0 {
            return Err(VckError::ChecksumMismatch);
        }
        let payload_len = u32::from_le_bytes(table[44..48].try_into().unwrap()) as usize;
        let payload_start = ACPI_HANDOVER_FIXED_SIZE;
        let payload_end = payload_start
            .checked_add(payload_len)
            .ok_or(VckError::ValidationFailed("ACPI payload length overflow"))?;
        if payload_end > table.len() {
            return Err(VckError::SizeMismatch {
                expected: payload_end,
                actual: table.len(),
            });
        }
        Ok(&table[payload_start..payload_end])
    }
}
