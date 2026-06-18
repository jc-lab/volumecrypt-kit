// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Driver-side loader handover reader.
//!
//! The UEFI loader stages the msgpack payload in an `EfiRuntimeServicesData`
//! buffer and publishes a small [`HandoverLocator`] (the buffer's physical
//! address + length, itself msgpack) in a UEFI runtime variable (the payload
//! type's `VAR_NAME` under `VAR_GUID`, `RUNTIME_ACCESS`). The driver reads the
//! locator via `ExGetFirmwareEnvironmentVariable`, maps the physical payload
//! buffer with `MmMapIoSpace`, and decodes the payload.
//!
//! Rationale: kernel-mode `ZwQuerySystemInformation(SystemFirmwareTableInformation,
//! provider "ACPI")` returns `STATUS_NOT_IMPLEMENTED` on current Windows, so an
//! ACPI-table transport could not be read from the driver. UEFI runtime variables
//! are readable from kernel mode and survive into the OS; the firmware keeps the
//! `EfiRuntimeServicesData` payload pages reserved, so the recorded physical
//! address stays valid at runtime.

use alloc::vec::Vec;
use vck_common::{
    handover::payload::{decode_locator, HandoverLocator, HandoverPayload},
    VckError, VckResult,
};
use wdk_sys::{
    ntddk::{ExFreePool, MmMapIoSpace, MmUnmapIoSpace},
    GUID, LARGE_INTEGER, NTSTATUS,
};

use crate::nt::UnicodeString;

const POOL_FLAG_NON_PAGED: u64 = 0x0000_0000_0000_0040;
const VCK_POOL_TAG: u32 = u32::from_le_bytes(*b"VCKH");

const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023u32 as i32;

/// `MEMORY_CACHING_TYPE::MmCached` — payload buffer is ordinary RAM.
const MM_CACHED: wdk_sys::MEMORY_CACHING_TYPE = wdk_sys::_MEMORY_CACHING_TYPE::MmCached;

/// Guard against a corrupt/hostile locator length mapping an absurd region.
const MAX_PAYLOAD_LEN: usize = 64 * 1024;

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

/// Read the loader handover and deserialize it into `P`.
///
/// Reads the [`HandoverLocator`] from the UEFI variable (name/GUID come from the
/// payload type `P::VAR_NAME` / `P::VAR_GUID`), maps the physical
/// `EfiRuntimeServicesData` payload buffer it points at, and decodes the
/// payload. Returns `NotFound` when no loader published the variable (the normal
/// case when booting without the loader).
pub fn read_handover<P: HandoverPayload>() -> VckResult<P> {
    let loc_bytes = read_handover_variable(P::VAR_NAME, P::VAR_GUID)?;
    let locator = decode_locator(&loc_bytes)?;
    let payload = read_handover_payload(&locator)?;
    vck_common::handover::payload::decode_payload::<P>(&payload)
}

/// Map the physical payload buffer the locator points at, copy it into an owned
/// `Vec`, then zeroize the mapped source (it held the plaintext VMK) and unmap.
fn read_handover_payload(locator: &HandoverLocator) -> VckResult<Vec<u8>> {
    let len = locator.length as usize;
    if len == 0 || locator.length > MAX_PAYLOAD_LEN as u64 {
        return Err(VckError::InvalidData(
            "handover payload length out of range",
        ));
    }

    let phys = LARGE_INTEGER {
        QuadPart: locator.address as i64,
    };
    // SAFETY: maps `len` bytes of physical RAM (an EfiRuntimeServicesData region
    // the firmware keeps reserved) into a system VA; runs at PASSIVE_LEVEL in
    // DriverEntry.
    let mapped = unsafe { MmMapIoSpace(phys, len as wdk_sys::SIZE_T, MM_CACHED) } as *mut u8;
    if mapped.is_null() {
        crate::vck_log!(
            "read_handover: MmMapIoSpace(0x{:x}, {}) failed",
            locator.address,
            len
        );
        return Err(VckError::Io("MmMapIoSpace(handover payload) failed".into()));
    }

    // SAFETY: `mapped` is valid for `len` bytes for the lifetime of the mapping.
    let out = unsafe {
        let v = core::slice::from_raw_parts(mapped, len).to_vec();
        core::ptr::write_bytes(mapped, 0, len);
        MmUnmapIoSpace(mapped.cast(), len as wdk_sys::SIZE_T);
        v
    };
    crate::vck_log!("read_handover: payload mapped ({} bytes)", out.len());
    Ok(out)
}

/// Read the raw value of the handover UEFI variable (the msgpack
/// [`HandoverLocator`]) into an owned buffer.
fn read_handover_variable(var_name: &str, var_guid: [u8; 16]) -> VckResult<Vec<u8>> {
    let name = UnicodeString::new(var_name);
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

    // Copy into an owned Vec, then zeroize + free the pool buffer. The variable
    // now carries only the locator (no VMK), but we keep the zeroize for hygiene.
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
