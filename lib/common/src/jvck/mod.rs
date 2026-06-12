// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! JVCK default metadata format: on-disk layout, key derivation, and a
//! volume-backed `EncryptedOffsetStore` implementation.
//!
//! Layout summary (see docs/jvck-format.md for the authoritative tables):
//! - A replica region is `metadata_size` bytes (>= 128 KiB) and contains a
//!   fixed 512-byte Metadata block plus vendor-specific data.
//! - Header replica: `[Metadata][vendor]`. Footer replica: `[vendor][Metadata]`
//!   so the footer Metadata block lands at the very end of the volume.

pub mod metadata;
pub mod options;
pub mod store;

pub use metadata::{DerivedKeys, JvckHeader, JvckSecrets, METADATA_BLOCK_SIZE};
pub use options::{JvckMetadataOptions, MIN_METADATA_SIZE};
pub use store::JvckMetadataStore;
