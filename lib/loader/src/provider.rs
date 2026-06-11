// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Loader provider interface.
//!
//! A sample loader implements [`LoaderProvider`] to tell the framework which
//! volume to protect, what handover payload to publish for the driver, and how
//! to chainload the next EFI image. See ARCH.md "lib/loader" for the contract.

use vck_common::handover::payload::HandoverPayload;
use vck_common::types::{EncryptedOffset, Guid};
use vck_common::VckResult;

// The borrowed device path is the unsized `uefi::proto::device_path::DevicePath`;
// the owned form in uefi 0.37 is `Box<DevicePath>` (via `DevicePath::to_boxed`).
// `LoaderConfig` must own its value, so we alias to the boxed form here.
pub type DevicePath = alloc::boxed::Box<uefi::proto::device_path::DevicePath>;

/// Interface a sample loader implements to drive `vck-loader`.
///
/// The associated [`Payload`](LoaderProvider::Payload) type MUST match the
/// driver-side `VolumeProvider::Payload`, so the loader serializes and the
/// driver deserializes the same concrete handover type (no `dyn Any`).
pub trait LoaderProvider: 'static {
    /// Handover payload type (same concrete type used by `VolumeProvider`).
    type Payload: HandoverPayload;

    /// Called once at loader initialization.
    ///
    /// Returns the loader configuration: the handover payload to publish, the
    /// next EFI image to chainload, and optionally AES-XTS key material for the
    /// high-level transparent decryption path. Boot services are reached through
    /// the `uefi::boot::*` free functions (uefi 0.37), so no table is passed in.
    fn on_init(&self) -> VckResult<LoaderConfig<Self::Payload>>;

    /// Low-level Block IO read hook.
    ///
    /// Only used when [`LoaderConfig::crypto`] is `None`. In the high-level
    /// (`Some(LoaderCrypto)`) path the framework performs AES-XTS itself and
    /// this default no-op is never invoked.
    fn read_hook(&self, lba: u64, buf: &mut [u8]) -> VckResult<()> {
        // Default implementation: no hook (handled by lib in the high-level path).
        let _ = (lba, buf);
        Ok(())
    }
}

/// Loader configuration returned by [`LoaderProvider::on_init`].
pub struct LoaderConfig<P: HandoverPayload> {
    /// Handover data serialized into the ACPI table for the driver.
    pub handover_payload: P,
    /// Path of the next EFI binary to chainload (e.g. the OS boot manager).
    pub next_loader: DevicePath,
    /// AES-XTS key material for the high-level path. `None` selects the
    /// low-level [`LoaderProvider::read_hook`] path instead.
    pub crypto: Option<LoaderCrypto>,
}

/// AES-XTS key material for the high-level transparent decryption path.
pub struct LoaderCrypto {
    /// GPT unique partition GUID of the volume whose Block IO is hooked.
    pub partition_guid: Guid,
    /// AES-XTS data (encryption) key.
    pub key1: [u8; 32],
    /// AES-XTS tweak key.
    pub key2: [u8; 32],
    /// Absolute starting LBA of the data (encryption target) region. The hooked
    /// read computes `rel = lba - offset_sector` from this value.
    pub offset_sector: u64,
    /// Progressive-encryption boundary and total data-region sector count.
    pub encrypted_offset: EncryptedOffset,
}
