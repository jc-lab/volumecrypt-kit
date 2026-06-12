// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! `vck-sample-loader` — sample UEFI loader built on `vck-loader`.
//!
//! Implements [`VckLoaderProvider`] and runs the lib/loader driver routine:
//! read `vck.json`, decrypt the OS volume footer metadata, install Block IO
//! hooks, publish the ACPI handover table, then chainload the next OS loader.
//! See ARCH.md "sample/loader" and "시스템 볼륨 부팅 흐름".

#![no_std]
#![no_main]

extern crate alloc;

mod provider;

use uefi::prelude::*;

use crate::provider::VckLoaderProvider;

/// UEFI application entry point (uefi 0.37 `#[entry]`).
///
/// The `#[entry]` macro initializes the system table / boot services; the
/// `global_allocator` and `panic_handler` uefi features provide the allocator
/// and panic handler. `helpers::init()` installs the logger for diagnostics.
#[entry]
fn efi_main() -> Status {
    let _ = uefi::helpers::init();
    vck_loader::vck_log!("efi_main: entered");

    let provider = VckLoaderProvider;

    // Drive the loader: read vck.json, decrypt the footer with the VMK, install
    // the transparent Block IO read hooks, inject the ACPI handover table, then
    // chainload the OS boot manager. On success `run` does not return.
    match vck_loader::run(&provider) {
        Ok(()) => {
            vck_loader::vck_log!("chainloaded image returned unexpectedly");
            log::warn!("vck-loader: chainloaded image returned unexpectedly");
            Status::SUCCESS
        }
        Err(err) => {
            vck_loader::vck_log!("boot failed: {}", err);
            log::error!("vck-loader: boot failed: {err}");
            Status::LOAD_ERROR
        }
    }
}
