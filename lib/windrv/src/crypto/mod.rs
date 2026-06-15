// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! AES-256-XTS cipher + async pipeline for the filter data path.
//!
//! The framework owns no cipher-selection policy: the sample builds the
//! [`VolumeCipher`](vck_common::VolumeCipher) in its `VolumeProvider::on_attach`
//! and hands it to the framework via `IoConfig::Encrypted`. [`AesXtsCipher`] is
//! the default JVCK suite cipher the sample uses (and the AES bench self-test).

pub mod aes_xts;
pub mod pipeline;

pub use aes_xts::AesXtsCipher;
pub use pipeline::CryptoPipeline;
