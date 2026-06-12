// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! `vck-loader` — UEFI loader framework for volumecrypt-kit.
//!
//! This crate provides the loader-side mechanisms described in `docs/architecture.md`
//! ("lib/loader"):
//!
//! - [`LoaderProvider`]: the trait a sample loader implements to drive the
//!   framework (configuration + handover payload + optional read hook).
//! - Block IO hooking engine ([`hook`]): hooks `EFI_BLOCK_IO_PROTOCOL` and
//!   `EFI_BLOCK_IO2_PROTOCOL` so that the OS volume data region is decrypted
//!   transparently while it is read during boot.
//! - Handover ([`handover`]): publishes the driver handover payload as a UEFI
//!   runtime variable (the driver reads it at OS runtime).
//! - Chainloading ([`chainload`]): loads and starts the next EFI image
//!   (the OS boot manager).
//!
//! Full compilation targets a UEFI triple and requires the WEDK toolchain
//! (`G:\`, see `AGENTS.md`); host builds are not expected.

#![no_std]

extern crate alloc;

pub mod chainload;
pub mod cpu;
pub mod debug;
pub mod handover;
pub mod hook;
pub mod provider;

// Public API re-exports (see docs/architecture.md "LoaderProvider 트레이트").
pub use provider::{LoaderConfig, LoaderCrypto, LoaderProvider};

// Re-export the hooking engine entry point for sample loaders.
pub use hook::BlockIoHookEngine;

use vck_common::VckResult;

/// Drive the full loader flow for `provider`:
///
///   1. `on_init` — read config, decrypt footer metadata, derive crypto;
///   2. if a high-level [`LoaderCrypto`] is present, install the transparent
///      Block IO read hooks (they intentionally stay installed across the
///      chainload so the OS loader reads the data region decrypted);
///   3. inject the ACPI handover table (`VCKD`) into the XSDT for the driver;
///   4. chainload the next OS loader.
///
/// On success control passes to the chained image and this does not return;
/// any `Err` should abort the boot.
pub fn run<P: LoaderProvider>(provider: &P) -> VckResult<()> {
    vck_log!("run: start");
    // Report AES-NI support and ensure the SSE/XMM control bits are set before
    // any AES-NI code (cipher construction / Block IO decrypt hook) runs.
    cpu::report_and_enable_xmm();
    let config = provider.on_init()?;
    vck_log!("run: on_init ok (crypto={})", config.crypto.is_some());

    if let Some(crypto) = config.crypto {
        // Leak the engine to a stable 'static address: the hooked read routine
        // recovers it via a side table keyed by protocol pointer, and the hooks
        // must outlive the chainload (the OS loader keeps reading through them).
        let engine = alloc::boxed::Box::leak(alloc::boxed::Box::new(BlockIoHookEngine::new(crypto)?));
        engine.install()?;
        vck_log!("run: block io hook installed");
    }

    handover::install_handover(&config.handover_payload)?;
    vck_log!("run: handover published (UEFI variable)");
    chainload::chainload_next(&config.next_loader)
}
