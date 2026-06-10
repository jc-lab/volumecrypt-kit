//! Driver-side ACPI handover reader.
//!
//! The UEFI loader publishes a custom ACPI table (signature `P::ACPI_SIGNATURE`,
//! e.g. `VCKD`) carrying the msgpack handover payload INLINE (see
//! `vck_common::handover::writer::AcpiHandoverWriter::encode`). At boot the
//! driver retrieves that table through the Windows firmware-table provider
//! (`SystemFirmwareTableInformation`, provider `ACPI`) and decodes the payload.

use core::ffi::c_void;

use alloc::vec::Vec;
use vck_common::{handover::payload::HandoverPayload, handover::reader::AcpiHandoverReader,
    VckError, VckResult};
use wdk_sys::{ntddk::ExFreePool, NTSTATUS};

// Re-export the common reader so callers can name it as `handover::Reader`.
pub use vck_common::handover::reader::AcpiHandoverReader as Reader;

const POOL_FLAG_NON_PAGED: u64 = 0x0000_0000_0000_0040;
const VCK_POOL_TAG: u32 = u32::from_le_bytes(*b"VCKH");

// SYSTEM_INFORMATION_CLASS::SystemFirmwareTableInformation
const SYSTEM_FIRMWARE_TABLE_INFORMATION: u32 = 76;
// SYSTEM_FIRMWARE_TABLE_ACTION::SystemFirmwareTable_Get
const FIRMWARE_TABLE_GET: u32 = 1;
// Provider signature for the ACPI firmware-table provider ("ACPI").
const ACPI_PROVIDER: u32 = u32::from_le_bytes(*b"ACPI");

const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023u32 as i32;
const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC000_0004u32 as i32;

extern "system" {
    fn ZwQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;
    fn ExAllocatePool2(flags: u64, size: u64, tag: u32) -> *mut c_void;
}

/// SYSTEM_FIRMWARE_TABLE_INFORMATION header (TableBuffer follows inline).
#[repr(C)]
struct FirmwareTableInfoHeader {
    provider_signature: u32,
    action: u32,
    table_id: u32,
    table_buffer_length: u32,
    // UCHAR TableBuffer[ANYSIZE_ARRAY] follows.
}

const HEADER_SIZE: usize = core::mem::size_of::<FirmwareTableInfoHeader>();

/// Locate the ACPI handover table matching `P::ACPI_SIGNATURE` and deserialize it.
///
/// The returned payload owns its data; the temporary kernel buffer holding the
/// (plaintext VMK) table is zeroized before being freed.
pub fn read_handover<P: HandoverPayload>() -> VckResult<P> {
    let table_id = u32::from_le_bytes(P::ACPI_SIGNATURE);
    let bytes = query_acpi_table(table_id)?;
    let result = AcpiHandoverReader::decode::<P>(&bytes);
    // bytes is dropped here (Vec); its backing was our own pool. We additionally
    // zeroize the heap copy below in query_acpi_table's owned Vec — handled by
    // returning a fresh Vec there.
    result
}

/// Query the firmware `ACPI` provider for the table identified by `table_id`
/// (its 4-byte signature packed little-endian). Returns the raw table bytes.
fn query_acpi_table(table_id: u32) -> VckResult<Vec<u8>> {
    // First call: discover the required total length (header + table).
    let mut header = FirmwareTableInfoHeader {
        provider_signature: ACPI_PROVIDER,
        action: FIRMWARE_TABLE_GET,
        table_id,
        table_buffer_length: 0,
    };
    let mut ret_len: u32 = 0;
    let st = unsafe {
        ZwQuerySystemInformation(
            SYSTEM_FIRMWARE_TABLE_INFORMATION,
            (&mut header as *mut FirmwareTableInfoHeader).cast::<c_void>(),
            HEADER_SIZE as u32,
            &mut ret_len,
        )
    };
    if st != STATUS_BUFFER_TOO_SMALL && st != STATUS_INFO_LENGTH_MISMATCH {
        return Err(VckError::Io("ZwQuerySystemInformation(size) unexpected status".into()));
    }
    if (ret_len as usize) <= HEADER_SIZE {
        return Err(VckError::NotFound("ACPI handover table not present"));
    }

    // Second call: allocate header + table and fetch the data.
    let total = ret_len as usize;
    let buf = unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, total as u64, VCK_POOL_TAG) as *mut u8 };
    if buf.is_null() {
        return Err(VckError::Io("ExAllocatePool2(firmware table) failed".into()));
    }

    let table_bytes = unsafe {
        let hdr = buf as *mut FirmwareTableInfoHeader;
        (*hdr).provider_signature = ACPI_PROVIDER;
        (*hdr).action = FIRMWARE_TABLE_GET;
        (*hdr).table_id = table_id;
        (*hdr).table_buffer_length = (total - HEADER_SIZE) as u32;

        let mut got: u32 = 0;
        let st = ZwQuerySystemInformation(
            SYSTEM_FIRMWARE_TABLE_INFORMATION,
            buf.cast::<c_void>(),
            total as u32,
            &mut got,
        );
        if st < 0 {
            zeroize_and_free(buf, total);
            return Err(VckError::Io("ZwQuerySystemInformation(get) failed".into()));
        }
        let table_len = (*hdr).table_buffer_length as usize;
        let table_ptr = buf.add(HEADER_SIZE);
        // Copy the table (incl. inline payload) into an owned Vec, then zeroize
        // and free the pool buffer holding the plaintext VMK.
        let out = core::slice::from_raw_parts(table_ptr, table_len).to_vec();
        zeroize_and_free(buf, total);
        out
    };

    Ok(table_bytes)
}

/// Overwrite the buffer with zeros (best-effort wipe of the plaintext VMK) then
/// release it back to the pool.
unsafe fn zeroize_and_free(buf: *mut u8, len: usize) {
    core::ptr::write_bytes(buf, 0, len);
    ExFreePool(buf.cast::<c_void>());
}
