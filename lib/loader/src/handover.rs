//! ACPI handover (loader side).
//!
//! Thin wrapper over `vck_common`'s `AcpiHandoverWriter` that installs the
//! custom ACPI configuration table (e.g. `VCKD`) carrying the driver handover
//! payload. See ARCH.md "UEFI→Driver 핸드오버" and the boot flow step 4.

use vck_common::handover::payload::HandoverPayload;
use vck_common::handover::writer::AcpiHandoverWriter;
use vck_common::VckResult;

// Re-export so sample loaders can reference the writer through this module.
pub use vck_common::handover::writer::AcpiHandoverWriter as HandoverWriter;

/// Builds the ACPI handover table for `payload` and installs it as a UEFI
/// configuration table at `table_guid`.
///
/// The table signature/OEM id come from `P::ACPI_SIGNATURE` / `P::ACPI_OEM_ID`.
/// The payload is msgpack-encoded into an `EfiRuntimeServicesData` buffer whose
/// physical address is recorded in the table; the driver later reads it back
/// via `AcpiHandoverReader`.
///
/// SECURITY: the buffer holds the plaintext VMK. The driver must copy it into
/// protected memory and zeroize the ACPI buffer immediately after boot (see
/// ARCH.md "키 수명·zeroize").
pub fn install_handover<P: HandoverPayload>(
    payload: &P,
    table_guid: &'static uefi::Guid,
) -> VckResult<()> {
    // TODO(loader): in the high-level path the physical address of the runtime
    // buffer is recorded by `install_uefi` itself. Confirm the table layout
    // (physical_address pointing at the msgpack buffer) matches what
    // AcpiHandoverReader expects on the driver side.
    let writer = AcpiHandoverWriter::new::<P>();
    writer.install_uefi(payload, table_guid)
}
