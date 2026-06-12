// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Loader-side shared types.
//!
//! `vck-loader` provides mechanism only: a sample loader drives the flow itself
//! (read config, open the OS volume, decrypt the metadata with its own chosen
//! algorithm, build a [`VolumeCipher`], install the Block IO hook, publish the
//! handover, chainload). See `sample/loader` for the reference flow.

use vck_common::types::{EncryptedOffset, Guid};

// The borrowed device path is the unsized `uefi::proto::device_path::DevicePath`;
// the owned form in uefi 0.37 is `Box<DevicePath>` (via `DevicePath::to_boxed`).
pub type DevicePath = alloc::boxed::Box<uefi::proto::device_path::DevicePath>;

/// Geometry the Block IO decrypt hook needs to map an absolute LBA to a
/// data-region-relative sector and decide whether it is ciphertext. The cipher
/// itself is supplied separately (the sample builds it), so no key material
/// lives here.
pub struct HookGeometry {
    /// GPT unique partition GUID of the volume whose Block IO is hooked.
    pub partition_guid: Guid,
    /// Absolute starting LBA of the data (encryption target) region. The hooked
    /// read computes `rel = lba - offset_sector` from this value.
    pub offset_sector: u64,
    /// Progressive-encryption boundary and total data-region sector count.
    pub encrypted_offset: EncryptedOffset,
}
