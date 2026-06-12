// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! UEFI loader -> driver handover payload for the JVCK sample.
//!
//! Because JVCK metadata lives in the volume footer, the handover carries only
//! the VMK and the target partition GUID. The driver re-derives FVEK,
//! encrypted_offset, and geometry by decrypting the footer metadata with the VMK.
//!
//! The payload travels as a UEFI runtime variable (the loader's `SetVariable` →
//! the driver's `ExGetFirmwareEnvironmentVariable`). The variable name and vendor
//! GUID below are the sample's choice — the framework reads them generically via
//! [`HandoverPayload::VAR_NAME`] / [`HandoverPayload::VAR_GUID`].

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use vck_common::{handover::payload::HandoverPayload, types::Guid};

/// UEFI variable name carrying the loader→driver handover (msgpack payload).
pub const HANDOVER_VAR_NAME: &str = "VckHandover";

/// Vendor GUID for [`HANDOVER_VAR_NAME`], as the 16 raw bytes of a Windows/UEFI
/// `GUID` ({59564B43-4448-564F-3132-2D5641522121}).
pub const HANDOVER_VAR_GUID: [u8; 16] = [
    0x43, 0x4b, 0x56, 0x59, // Data1 (LE) = 0x59564B43
    0x48, 0x44, // Data2 (LE) = 0x4448
    0x4f, 0x56, // Data3 (LE) = 0x564F
    0x31, 0x32, 0x2d, 0x56, 0x41, 0x52, 0x21, 0x21, // Data4
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VckHandoverPayload {
    /// Target OS volume's GPT partition GUID.
    pub partition_guid: Guid,
    /// Key used to decrypt the volume footer metadata and recover the FVEK.
    pub vmk: Vec<u8>,
}

impl HandoverPayload for VckHandoverPayload {
    const VAR_NAME: &'static str = HANDOVER_VAR_NAME;
    const VAR_GUID: [u8; 16] = HANDOVER_VAR_GUID;
}
