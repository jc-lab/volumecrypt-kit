//! Loader provider interface.
//!
//! A sample loader implements [`LoaderProvider`] to tell the framework which
//! volume to protect, what handover payload to publish for the driver, and how
//! to chainload the next EFI image. See ARCH.md "lib/loader" for the contract.

use vck_common::handover::payload::HandoverPayload;
use vck_common::types::EncryptedOffset;
use vck_common::VckResult;

// NOTE: ARCH.md spells the field type as `DevicePath`. In the `uefi` 0.37 crate
// the borrowed device path is the unsized `uefi::proto::device_path::DevicePath`
// and an owned one is `DevicePathBuffer`. `LoaderConfig` must own its value, so
// we alias to the owned buffer type here.
// TODO(loader): confirm `DevicePathBuffer` is the right owned type for the
// installed `uefi` version, or switch to a custom owned wrapper if needed.
pub type DevicePath = uefi::proto::device_path::DevicePathBuffer;

/// Boot-time services handle as seen by the provider.
///
/// ARCH.md writes `on_init(&self, boot_services: &BootServices)`. The `uefi`
/// 0.37 crate moved boot services to free functions in `uefi::boot::*` and no
/// longer exposes a borrowable `BootServices` table, so this alias keeps the
/// ARCH.md signature shape while pointing at the system table.
// TODO(loader): the sample driver routine should prefer `uefi::boot::*` free
// functions directly; this alias only preserves the documented signature.
pub type BootServices = uefi::table::system_table_boot;

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
    /// high-level transparent decryption path.
    fn on_init(&self, boot_services: &BootServices) -> VckResult<LoaderConfig<Self::Payload>>;

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
