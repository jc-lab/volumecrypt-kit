// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

pub mod payload;
pub mod reader;
pub mod writer;

/// UEFI variable name carrying the loader→driver handover (msgpack payload).
///
/// Kernel-mode `ZwQuerySystemInformation(SystemFirmwareTableInformation, "ACPI")`
/// returns `STATUS_NOT_IMPLEMENTED` on current Windows, so the ACPI-table path is
/// unusable from the driver. Instead the loader publishes the handover as a UEFI
/// runtime variable (`SetVariable`, RUNTIME_ACCESS) and the driver reads it with
/// `ExGetFirmwareEnvironmentVariable`. The variable value is the raw msgpack
/// payload (see [`payload::encode_payload`] / [`payload::decode_payload`]).
pub const HANDOVER_VAR_NAME: &str = "VckHandover";

/// Vendor GUID for [`HANDOVER_VAR_NAME`], as the 16 raw bytes of a Windows/UEFI
/// `GUID` ({59564B43-4448-564F-3132-2D5641522121}). Both the loader (`uefi::Guid`)
/// and the driver (`wdk_sys::GUID`) construct their GUID from these same bytes.
pub const HANDOVER_VAR_GUID: [u8; 16] = [
    0x43, 0x4b, 0x56, 0x59, // Data1 (LE) = 0x59564B43
    0x48, 0x44, // Data2 (LE) = 0x4448
    0x4f, 0x56, // Data3 (LE) = 0x564F
    0x31, 0x32, 0x2d, 0x56, 0x41, 0x52, 0x21, 0x21, // Data4
];
