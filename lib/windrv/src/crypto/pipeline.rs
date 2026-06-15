// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Sector-wise AES-XTS read/write pipeline.
//!
//! Operates in **data-region-relative** sector space: the caller (filter/engine)
//! converts the absolute LBA to `rel = lba - offset_sector` for the first sector
//! of the buffer and guarantees the whole buffer lies inside the data region
//! (metadata-region I/O is passed through before reaching here).
//!
//! The `encrypted_offset` boundary may fall inside the buffer, so each sector is
//! decided independently: `rel < encrypted_offset` is ciphertext, otherwise it
//! is still plaintext.

use vck_common::VolumeCipher;

pub struct CryptoPipeline<'a> {
    cipher: &'a dyn VolumeCipher,
}

impl<'a> CryptoPipeline<'a> {
    pub fn new(cipher: &'a dyn VolumeCipher) -> Self {
        Self { cipher }
    }

    /// Decrypt a freshly-read buffer in place. Sectors at/after
    /// `encrypted_offset` are still plaintext and left untouched.
    pub fn decrypt_read(
        &self,
        first_rel_sector: u64,
        encrypted_offset: u64,
        buf: &mut [u8],
        sector_size: usize,
    ) {
        let total = buf.len() / sector_size;
        let n = if encrypted_offset <= first_rel_sector {
            0
        } else {
            ((encrypted_offset - first_rel_sector) as usize).min(total)
        };
        if n > 0 {
            self.cipher
                .decrypt_area(&mut buf[..n * sector_size], sector_size, first_rel_sector);
        }
    }

    /// Encrypt a write buffer in place before it goes down-stack. Sectors at/after
    /// `encrypted_offset` are written as plaintext.
    pub fn encrypt_write(
        &self,
        first_rel_sector: u64,
        encrypted_offset: u64,
        buf: &mut [u8],
        sector_size: usize,
    ) {
        let total = buf.len() / sector_size;
        let n = if encrypted_offset <= first_rel_sector {
            0
        } else {
            ((encrypted_offset - first_rel_sector) as usize).min(total)
        };
        if n > 0 {
            self.cipher
                .encrypt_area(&mut buf[..n * sector_size], sector_size, first_rel_sector);
        }
    }
}
