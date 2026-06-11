// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! ACPI handover (loader side).
//!
//! Thin wrapper over `vck_common`'s `AcpiHandoverWriter` that installs the
//! custom ACPI configuration table (e.g. `VCKD`) carrying the driver handover
//! payload. See ARCH.md "UEFI→Driver 핸드오버" and the boot flow step 4.

use alloc::format;

use uefi::runtime::{set_variable, VariableAttributes, VariableVendor};
use uefi::{CString16, Guid};
use vck_common::handover::payload::{encode_payload, HandoverPayload};
use vck_common::handover::{HANDOVER_VAR_GUID, HANDOVER_VAR_NAME};
use vck_common::{VckError, VckResult};

// Re-export so sample loaders can reference the writer through this module.
pub use vck_common::handover::writer::AcpiHandoverWriter as HandoverWriter;

/// Publish the loader→driver handover as a UEFI runtime variable.
///
/// The variable value is the raw msgpack `payload`. It is set with
/// `BOOTSERVICE_ACCESS | RUNTIME_ACCESS` (volatile — it only needs to live for
/// this boot) so the driver can read it at OS runtime via
/// `ExGetFirmwareEnvironmentVariable`.
///
/// (The earlier ACPI-XSDT-injection approach — `AcpiHandoverWriter::install_uefi`
/// — is unusable because kernel-mode `ZwQuerySystemInformation` returns
/// `STATUS_NOT_IMPLEMENTED` for the firmware-table provider.)
///
/// SECURITY: the value holds the plaintext VMK. The driver copies it into
/// protected memory after reading; the variable is volatile and disappears on
/// reset.
pub fn install_handover<P: HandoverPayload>(payload: &P) -> VckResult<()> {
    let data = encode_payload(payload)?;
    let name = CString16::try_from(HANDOVER_VAR_NAME)
        .map_err(|_| VckError::InvalidData("handover variable name not valid UCS-2"))?;
    let vendor = VariableVendor(Guid::from_bytes(HANDOVER_VAR_GUID));
    let attrs = VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
    set_variable(&name, &vendor, attrs, &data)
        .map_err(|e| VckError::Io(format!("SetVariable(handover) failed: {e:?}")))
}
