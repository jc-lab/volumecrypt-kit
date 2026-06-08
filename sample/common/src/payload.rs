//! UEFI loader -> driver handover payload for the JVCK sample.
//!
//! Because JVCK metadata lives in the volume footer, the handover carries only
//! the VMK and the target partition GUID. The driver re-derives FVEK,
//! encrypted_offset, and geometry by decrypting the footer metadata with the VMK.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use vck_common::{handover::payload::HandoverPayload, types::Guid};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VckHandoverPayload {
    /// Target OS volume's GPT partition GUID.
    pub partition_guid: Guid,
    /// Key used to decrypt the volume footer metadata and recover the FVEK.
    pub vmk: Vec<u8>,
}

impl HandoverPayload for VckHandoverPayload {
    const ACPI_SIGNATURE: [u8; 4] = *b"VCKD";
    const ACPI_OEM_ID: [u8; 6] = *b"SAMPLE";
}
