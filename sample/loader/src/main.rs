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
use vck_loader::LoaderProvider;

use crate::provider::VckLoaderProvider;

/// UEFI application entry point (uefi 0.37 `#[entry]`).
#[entry]
fn efi_main() -> Status {
    // uefi 0.37 wires up the global allocator and panic handler via the `uefi`
    // crate's `helpers`/`global_allocator` features when enabled. Initialize
    // services so `uefi::boot::*` free functions are usable.
    // TODO(loader): call `uefi::helpers::init()` (and enable the matching uefi
    // feature) for logging + allocator + panic handler wiring.

    let provider = VckLoaderProvider;

    // TODO(loader): the driver routine below belongs in lib/loader (e.g. a
    // `vck_loader::run(&provider)`); inlined here until that entry exists.
    //
    //   1. let config = provider.on_init(boot_services)?;
    //   2. if let Some(crypto) = config.crypto {
    //          let mut engine = BlockIoHookEngine::new(crypto);
    //          engine.install()?;
    //      }
    //   3. handover::install_handover(&config.handover_payload, &VCKD_TABLE_GUID)?;
    //   4. zeroize loader-local VMK/FVEK copies;
    //   5. chainload::chainload_next(&config.next_loader)?;
    let _ = &provider;
    let _ = VckLoaderProvider::on_init;

    Status::SUCCESS
}
