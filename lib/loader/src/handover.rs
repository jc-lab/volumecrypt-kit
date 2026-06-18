// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Loader→driver handover (loader side).
//!
//! Serializes the handover payload into a buffer the loader allocates as
//! `EfiRuntimeServicesData`, and publishes only a small [`HandoverLocator`]
//! (physical address + length, itself msgpack) as a UEFI runtime variable. The
//! driver reads the locator, then maps the physical buffer to recover the
//! payload. See docs/architecture.md "UEFI→Driver 핸드오버" and the boot flow step 4.

use alloc::format;

use uefi::boot::{allocate_pool, MemoryType};
use uefi::runtime::{set_variable, VariableAttributes, VariableVendor};
use uefi::{CString16, Guid};
use vck_common::handover::payload::{
    encode_locator, encode_payload, HandoverLocator, HandoverPayload,
};
use vck_common::{VckError, VckResult};

/// Publish the loader→driver handover.
///
/// 1. The msgpack payload is serialized into a buffer allocated as
///    `EfiRuntimeServicesData` — pages the firmware keeps reserved across the
///    handoff to the OS, so the driver can read them at runtime. The buffer is
///    intentionally **leaked**: it must outlive the loader and survive
///    `ExitBootServices` into the OS, where the driver consumes (and zeroizes)
///    it.
/// 2. A [`HandoverLocator`] (the buffer's physical address + length) is written
///    to the UEFI variable named by the payload type (`P::VAR_NAME` /
///    `P::VAR_GUID`) with `BOOTSERVICE_ACCESS | RUNTIME_ACCESS` (volatile — it
///    only needs to live for this boot), so the driver can read it via
///    `ExGetFirmwareEnvironmentVariable`.
///
/// In the loader's pre-`ExitBootServices` environment memory is identity-mapped,
/// so the pointer returned by `allocate_pool` is also the physical address
/// recorded in the locator.
///
/// SECURITY: the payload buffer holds the plaintext VMK. The driver copies it
/// into protected memory and zeroizes the source after reading; the locator
/// variable is volatile and disappears on reset.
pub fn install_handover<P: HandoverPayload>(payload: &P) -> VckResult<()> {
    let data = encode_payload(payload)?;

    // 1. Stage the payload in EfiRuntimeServicesData memory (leaked on purpose).
    let len = data.len();
    let buf = allocate_pool(MemoryType::RUNTIME_SERVICES_DATA, len).map_err(|e| {
        VckError::Io(format!(
            "allocate_pool(RUNTIME_SERVICES_DATA, {len}) failed: {e:?}"
        ))
    })?;
    // SAFETY: `buf` points to `len` freshly allocated, writable bytes; `data`
    // owns `len` bytes; the regions do not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf.as_ptr(), len);
    }
    // Identity-mapped pre-ExitBootServices: the virtual pointer is the physical
    // address the driver later maps.
    let address = buf.as_ptr() as u64;

    // 2. Publish the locator in the UEFI variable.
    let locator = HandoverLocator::new(address, len as u64);
    let loc_bytes = encode_locator(&locator)?;
    let name = CString16::try_from(P::VAR_NAME)
        .map_err(|_| VckError::InvalidData("handover variable name not valid UCS-2"))?;
    let vendor = VariableVendor(Guid::from_bytes(P::VAR_GUID));
    let attrs = VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
    set_variable(&name, &vendor, attrs, &loc_bytes)
        .map_err(|e| VckError::Io(format!("SetVariable(handover locator) failed: {e:?}")))
}
