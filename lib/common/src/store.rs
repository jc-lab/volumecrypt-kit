// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    types::{EncryptedOffset, VolumeState},
    VckResult,
};

/// Abstraction over raw sector read/write of a single volume.
///
/// Implemented differently per environment:
/// - UEFI loader: backed by `EFI_BLOCK_IO_PROTOCOL` (see `lib/common` uefi
///   feature, or `lib/loader`).
/// - Kernel driver: backed by the lower volume device (`lib/windrv`).
///
/// All offsets are absolute LBAs on the volume.
///
/// `Send + Sync` so a `JvckMetadataStore<S>` / `Arc<dyn SectorIo>` can be shared
/// with the background sweep thread.
pub trait SectorIo: Send + Sync {
    fn sector_size(&self) -> u32;
    /// Total raw sector count of the volume (partition capacity).
    fn total_sectors(&self) -> u64;
    fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> VckResult<()>;
    fn write_sectors(&self, lba: u64, buf: &[u8]) -> VckResult<()>;
}

/// Persists the progressive-encryption offset durably so encryption can resume
/// after a reboot or power loss.
///
/// The default JVCK implementation (`jvck::JvckMetadataStore`) writes the value
/// to every configured header/footer replica.
pub trait EncryptedOffsetStore: Send + Sync + 'static {
    fn load(&self) -> VckResult<EncryptedOffset>;
    fn store(&self, offset: &EncryptedOffset) -> VckResult<()>;
    fn flush(&self) -> VckResult<()>;

    /// Load the persisted sweep direction (encrypt vs decrypt). Defaults to
    /// `Encrypt` for stores that do not track it.
    fn load_state(&self) -> VckResult<VolumeState> {
        Ok(VolumeState::Encrypt)
    }

    /// Persist the sweep direction durably (so a reboot resumes the right
    /// direction). Default no-op for stores that do not track it.
    fn store_state(&self, _state: VolumeState) -> VckResult<()> {
        Ok(())
    }
}
