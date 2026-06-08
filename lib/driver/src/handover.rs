//! Driver-side ACPI handover reader wrapper around `vck_common`.

use vck_common::{handover::payload::HandoverPayload, VckResult};

// Re-export the common reader so callers can name it as `handover::Reader`.
pub use vck_common::handover::reader::AcpiHandoverReader as Reader;

/// Locate the ACPI table matching `P::ACPI_SIGNATURE` and deserialize it.
///
/// On success the caller should copy the VMK into protected memory and then
/// zeroize the ACPI buffer (see ARCH.md "key lifetime / zeroize").
pub fn read_handover<P: HandoverPayload>() -> VckResult<P> {
    // TODO(driver): obtain the ACPI table region (AuxKlibQueryModuleInformation
    // / firmware table provider), then:
    //   Reader::find_and_decode::<P>(tables)
    todo!("acquire ACPI tables and Reader::find_and_decode")
}
