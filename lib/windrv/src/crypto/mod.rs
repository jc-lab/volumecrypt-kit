// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Async AES-XTS encryption pipeline for the filter data path.

pub mod aes_xts;
pub mod pipeline;

pub use aes_xts::AesXtsCipher;
pub use pipeline::CryptoPipeline;
