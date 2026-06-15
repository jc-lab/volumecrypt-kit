// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! `vck-loader` — UEFI loader framework for volumecrypt-kit.
//!
//! This crate provides the loader-side **mechanisms** described in
//! `docs/architecture.md` ("lib/loader"); the sample loader drives the flow
//! itself and owns the crypto policy:
//!
//! - [`init`]: start banner + enable the SSE/XMM control bits AES-NI needs.
//! - Block IO hooking engine ([`hook::BlockIoHookEngine`]): given a sample-built
//!   [`HookGeometry`] + [`VolumeCipher`](vck_common::VolumeCipher), hooks
//!   `EFI_BLOCK_IO_PROTOCOL` and
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

// Public API re-exports. The sample loader drives the flow itself with these
// building blocks (see `sample/loader`).
pub use provider::{DevicePath, HookGeometry};

// Re-export the hooking engine entry point for sample loaders.
pub use hook::BlockIoHookEngine;

/// Loader initialization: emit a start banner and report/enable the SSE/XMM
/// control bits required by AES-NI before any AES-NI code (cipher construction,
/// the Block IO decrypt hook) runs. Call this first from the sample's entry.
pub fn init() {
    vck_log!("init: start");
    cpu::report_and_enable_xmm();
}
