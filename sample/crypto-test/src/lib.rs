// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! `vck-crypto-test-driver`: an in-kernel self-test driver (builds to a `.sys`).
//!
//! Loaded by test-foundry in the VM to validate that the JVCK crypto primitives
//! (HKDF key derivation, Header CRC32, HMAC, AES-256-CBC EncryptedMetadata, and
//! AES-XTS sector crypto) behave identically in the kernel as on the host. Each
//! check prints PASS/FAIL via the driver debug channel; DriverEntry returns a
//! failure NTSTATUS if any check fails so the recipe can assert on it.
#![no_std]
#![allow(non_snake_case)]

extern crate alloc;

use core::panic::PanicInfo;
use log::info;

use wdk_alloc::WdkAllocator;
use wdk_sys::{DRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING};

mod tests;

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

/// # Safety
/// Called by the kernel with valid pointers.
#[no_mangle]
pub unsafe extern "system" fn DriverEntry(
    driver: *mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let _ = (driver, registry_path);
    vck_windrv::init_logger();
    let report = tests::run_all();
    info!(
        "crypto-test: {} passed, {} failed",
        report.passed,
        report.failed
    );
    // TODO(crypto-test): map report -> NTSTATUS (STATUS_SUCCESS / STATUS_UNSUCCESSFUL)
    // and unload cleanly (no device object needed).
    todo!("return STATUS based on report")
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    vck_windrv::debug::panic_print(info)
}
