// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Driver-side loader handover reader (UEFI runtime variable).
//!
//! The UEFI loader publishes the handover payload as a UEFI runtime variable
//! (the payload type's `VAR_NAME` under `VAR_GUID`), with `RUNTIME_ACCESS`, whose
//! value is the raw msgpack payload. The driver reads it at runtime via
//! `ExGetFirmwareEnvironmentVariable` and decodes it.
//!
//! Rationale: kernel-mode `ZwQuerySystemInformation(SystemFirmwareTableInformation,
//! provider "ACPI")` returns `STATUS_NOT_IMPLEMENTED` on current Windows, so an
//! ACPI-table transport could not be read from the driver. UEFI runtime variables
//! are readable from kernel mode and survive into the OS.

use alloc::vec::Vec;
use vck_common::{handover::payload::HandoverPayload, VckError, VckResult};
use wdk_sys::{ntddk::ExFreePool, GUID, NTSTATUS};

use crate::nt::UnicodeString;

const POOL_FLAG_NON_PAGED: u64 = 0x0000_0000_0000_0040;
const VCK_POOL_TAG: u32 = u32::from_le_bytes(*b"VCKH");

const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023u32 as i32;

extern "system" {
    fn ExGetFirmwareEnvironmentVariable(
        variable_name: *mut wdk_sys::UNICODE_STRING,
        vendor_guid: *mut GUID,
        value: *mut core::ffi::c_void,
        value_length: *mut u32,
        attributes: *mut u32,
    ) -> NTSTATUS;
    fn ExAllocatePool2(flags: u64, size: u64, tag: u32) -> *mut core::ffi::c_void;
}

/// Construct the vendor `GUID` from the shared raw bytes (Windows GUID layout:
/// `Data1`/`Data2`/`Data3` little-endian, `Data4` as-is).
fn handover_guid(b: [u8; 16]) -> GUID {
    GUID {
        Data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        Data2: u16::from_le_bytes([b[4], b[5]]),
        Data3: u16::from_le_bytes([b[6], b[7]]),
        Data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
    }
}

/// Read the loader handover UEFI variable and deserialize it into `P`.
///
/// The variable name/GUID come from the payload type (`P::VAR_NAME` /
/// `P::VAR_GUID`). Returns `NotFound` when no loader published the variable (the
/// normal case when booting without the loader).
pub fn read_handover<P: HandoverPayload>() -> VckResult<P> {
    let bytes = read_handover_variable(P::VAR_NAME, P::VAR_GUID)?;
    vck_common::handover::payload::decode_payload::<P>(&bytes)
}

/// Read the raw value of the handover UEFI variable into an owned buffer.
fn read_handover_variable(var_name: &str, var_guid: [u8; 16]) -> VckResult<Vec<u8>> {
    let name = UnicodeString::from_str(var_name);
    let mut guid = handover_guid(var_guid);

    // First call: discover the value length (pass a zero-length buffer).
    let mut len: u32 = 0;
    let mut dummy = [0u8; 1];
    let st = unsafe {
        ExGetFirmwareEnvironmentVariable(
            name.as_ptr(),
            &mut guid,
            dummy.as_mut_ptr().cast(),
            &mut len,
            core::ptr::null_mut(),
        )
    };
    if st != STATUS_BUFFER_TOO_SMALL || len == 0 {
        crate::vck_log!("read_handover: size probe status=0x{:08x} len={}", st, len);
        return Err(VckError::NotFound("handover variable not present"));
    }

    // Second call: fetch the value into our buffer.
    let total = len as usize;
    let buf =
        unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, total as u64, VCK_POOL_TAG) as *mut u8 };
    if buf.is_null() {
        return Err(VckError::Io("ExAllocatePool2(handover var) failed".into()));
    }
    let mut got = len;
    let st = unsafe {
        ExGetFirmwareEnvironmentVariable(
            name.as_ptr(),
            &mut guid,
            buf.cast(),
            &mut got,
            core::ptr::null_mut(),
        )
    };
    if st < 0 {
        unsafe {
            core::ptr::write_bytes(buf, 0, total);
            ExFreePool(buf.cast());
        }
        crate::vck_log!("read_handover: get status=0x{:08x}", st);
        return Err(VckError::Io(
            "ExGetFirmwareEnvironmentVariable(get) failed".into(),
        ));
    }

    // Copy into an owned Vec, then zeroize + free the pool buffer (it held the
    // plaintext VMK).
    let out = unsafe {
        let copy_len = (got as usize).min(total);
        let v = core::slice::from_raw_parts(buf, copy_len).to_vec();
        core::ptr::write_bytes(buf, 0, total);
        ExFreePool(buf.cast());
        v
    };
    crate::vck_log!("read_handover: variable read ok ({} bytes)", out.len());
    Ok(out)
}
