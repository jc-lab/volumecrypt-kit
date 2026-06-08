//! `vck-loader` — UEFI loader framework for volumecrypt-kit.
//!
//! This crate provides the loader-side mechanisms described in `ARCH.md`
//! ("lib/loader"):
//!
//! - [`LoaderProvider`]: the trait a sample loader implements to drive the
//!   framework (configuration + handover payload + optional read hook).
//! - Block IO hooking engine ([`hook`]): hooks `EFI_BLOCK_IO_PROTOCOL` and
//!   `EFI_BLOCK_IO2_PROTOCOL` so that the OS volume data region is decrypted
//!   transparently while it is read during boot.
//! - ACPI handover ([`handover`]): a thin wrapper over `vck_common`'s
//!   `AcpiHandoverWriter` that installs the custom (e.g. `VCKD`) table carrying
//!   the driver handover payload.
//! - Chainloading ([`chainload`]): loads and starts the next EFI image
//!   (the OS boot manager).
//!
//! Full compilation targets a UEFI triple and requires the WEDK toolchain
//! (`G:\`, see `AGENTS.md`); host builds are not expected.

#![no_std]

extern crate alloc;

pub mod chainload;
pub mod handover;
pub mod hook;
pub mod provider;

// Public API re-exports (see ARCH.md "LoaderProvider 트레이트").
pub use provider::{LoaderConfig, LoaderCrypto, LoaderProvider};

// Re-export the hooking engine entry point for sample loaders.
pub use hook::BlockIoHookEngine;
