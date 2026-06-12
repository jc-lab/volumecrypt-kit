// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Async AES-XTS encryption pipeline for the filter data path.

pub mod aes_xts;
pub mod pipeline;

pub use aes_xts::AesXtsCipher;
pub use pipeline::CryptoPipeline;

use alloc::boxed::Box;
use vck_common::{jvck::metadata::JvckHeader, VckResult, VolumeCipher};

/// Build the full-volume cipher for a JVCK volume from its **complete** parsed
/// metadata header (vendor_id, vendor_version, vendor_reserved, …) plus the FVEK
/// halves recovered from the EncryptedMetadata blob.
///
/// The default JVCK suite returns AES-256-XTS. A vendor integrating their own
/// full-volume-encryption algorithm matches on `header` here (e.g. on
/// `header.vendor_id` / `header.vendor_reserved`) and returns a different
/// [`VolumeCipher`] implementation. The cipher is selected from the whole
/// metadata, not just `vendor_id`.
pub fn build_volume_cipher(
    header: &JvckHeader,
    key1: [u8; 32],
    key2: [u8; 32],
) -> VckResult<Box<dyn VolumeCipher>> {
    let _ = header; // default suite ignores it; vendors dispatch on it.
    Ok(Box::new(AesXtsCipher::new(key1, key2)?))
}
