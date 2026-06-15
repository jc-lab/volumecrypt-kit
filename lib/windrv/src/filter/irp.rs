// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Filter IRP helpers.
//!
//! For now read/write are forwarded unchanged (transparent pass-through). The
//! AES-XTS interception (decrypt on read completion, encrypt via a shadow buffer
//! on write) will be layered on top of this.

use wdk_sys::{ntddk::IofCallDriver, NTSTATUS, PDEVICE_OBJECT, PIRP};

/// Forward `irp` to `lower_device` without consuming a stack location of our
/// own (we did not allocate one for it).
///
/// # Safety
/// `irp` must be a valid IRP currently owned by this driver, and `lower_device`
/// the device immediately below the filter.
pub unsafe fn pass_through(lower_device: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
    skip_current_stack_location(irp);
    IofCallDriver(lower_device, irp)
}

/// Equivalent of the `IoSkipCurrentIrpStackLocation` macro: reuse the current
/// stack location for the next (lower) driver.
unsafe fn skip_current_stack_location(irp: PIRP) {
    (*irp).CurrentLocation += 1;
    let csl = (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation;
    (*irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation = csl.add(1);
}
