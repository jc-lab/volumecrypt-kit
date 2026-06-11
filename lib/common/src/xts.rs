// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Shared AES-256-XTS volume sector cipher used by both the kernel driver and
//! the UEFI loader, so their on-disk crypto agrees by construction.
//!
//! **Tweak convention (authoritative):** the XTS tweak for a sector is its
//! **data-region-relative** sector number, i.e. `rel = absolute_lba - offset_sector`,
//! where `rel == 0` is the first encryptable sector. This matches the
//! `EncryptedOffset` semantics (also data-region relative). Callers MUST map
//! absolute LBAs to `rel` before invoking these methods, and MUST NOT call them
//! for sectors inside header/footer metadata regions (those pass through in
//! plaintext).
//!
//! Keys are two independent 256-bit halves (`key1` = data key, `key2` = tweak
//! key), giving AES-256-XTS.

use aes::cipher::KeyInit;
use aes::Aes256;
use xts_mode::{get_tweak_default, Xts128};

use crate::{VckError, VckResult};

pub struct XtsVolumeCipher {
    xts: Xts128<Aes256>,
}

impl XtsVolumeCipher {
    pub fn new(key1: &[u8; 32], key2: &[u8; 32]) -> VckResult<Self> {
        let cipher_1 =
            Aes256::new_from_slice(key1).map_err(|_| VckError::CryptoFailed("invalid XTS key1"))?;
        let cipher_2 =
            Aes256::new_from_slice(key2).map_err(|_| VckError::CryptoFailed("invalid XTS key2"))?;
        Ok(Self {
            xts: Xts128::new(cipher_1, cipher_2),
        })
    }

    /// Encrypt one sector in place. `rel_sector` is data-region relative.
    pub fn encrypt_sector(&self, rel_sector: u64, sector: &mut [u8]) {
        self.xts
            .encrypt_sector(sector, get_tweak_default(rel_sector as u128));
    }

    /// Decrypt one sector in place. `rel_sector` is data-region relative.
    pub fn decrypt_sector(&self, rel_sector: u64, sector: &mut [u8]) {
        self.xts
            .decrypt_sector(sector, get_tweak_default(rel_sector as u128));
    }

    /// Encrypt a contiguous buffer of `sector_size`-sized sectors, the first of
    /// which is data-region-relative sector `first_rel_sector`.
    pub fn encrypt_area(&self, buf: &mut [u8], sector_size: usize, first_rel_sector: u64) {
        self.xts.encrypt_area(
            buf,
            sector_size,
            first_rel_sector as u128,
            get_tweak_default,
        );
    }

    /// Decrypt a contiguous buffer (inverse of [`encrypt_area`]).
    pub fn decrypt_area(&self, buf: &mut [u8], sector_size: usize, first_rel_sector: u64) {
        self.xts.decrypt_area(
            buf,
            sector_size,
            first_rel_sector as u128,
            get_tweak_default,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const KEY1: [u8; 32] = [0x11; 32];
    const KEY2: [u8; 32] = [0x22; 32];

    #[test]
    fn sector_roundtrip() {
        let c = XtsVolumeCipher::new(&KEY1, &KEY2).unwrap();
        let plain: Vec<u8> = (0..512).map(|i| i as u8).collect();
        let mut buf = plain.clone();
        c.encrypt_sector(42, &mut buf);
        assert_ne!(buf, plain, "ciphertext must differ from plaintext");
        c.decrypt_sector(42, &mut buf);
        assert_eq!(buf, plain);
    }

    #[test]
    fn tweak_depends_on_sector() {
        let c = XtsVolumeCipher::new(&KEY1, &KEY2).unwrap();
        let plain = [0xABu8; 512];
        let mut a = plain;
        let mut b = plain;
        c.encrypt_sector(0, &mut a);
        c.encrypt_sector(1, &mut b);
        assert_ne!(a, b, "same plaintext at different sectors must differ");
    }

    #[test]
    fn area_matches_per_sector() {
        let c = XtsVolumeCipher::new(&KEY1, &KEY2).unwrap();
        let sector_size = 512usize;
        let first = 7u64;
        let plain: Vec<u8> = (0..sector_size * 3).map(|i| (i * 7) as u8).collect();

        // encrypt_area over 3 sectors
        let mut area = plain.clone();
        c.encrypt_area(&mut area, sector_size, first);

        // encrypt the same 3 sectors individually
        let mut manual = plain.clone();
        for s in 0..3u64 {
            let start = s as usize * sector_size;
            c.encrypt_sector(first + s, &mut manual[start..start + sector_size]);
        }
        assert_eq!(area, manual);

        // and it round-trips
        c.decrypt_area(&mut area, sector_size, first);
        assert_eq!(area, plain);
    }
}
