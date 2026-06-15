// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! AES-XTS kernel cipher: a thin wrapper over the shared
//! [`vck_common::XtsVolumeCipher`] so the driver and the UEFI loader use an
//! identical tweak convention (data-region-relative sector; see that module).

use vck_common::{VckResult, XtsVolumeCipher};

pub struct AesXtsCipher {
    inner: XtsVolumeCipher,
}

impl AesXtsCipher {
    pub fn new(key1: [u8; 32], key2: [u8; 32]) -> VckResult<Self> {
        Ok(Self {
            inner: XtsVolumeCipher::new(&key1, &key2)?,
        })
    }

    /// Decrypt one sector in place. `rel_sector` is data-region relative.
    pub fn decrypt_sector(&self, rel_sector: u64, buf: &mut [u8]) {
        self.inner.decrypt_sector(rel_sector, buf);
    }

    /// Encrypt one sector in place. `rel_sector` is data-region relative.
    pub fn encrypt_sector(&self, rel_sector: u64, buf: &mut [u8]) {
        self.inner.encrypt_sector(rel_sector, buf);
    }

    /// Encrypt a contiguous buffer of `sector_size`-byte sectors using the
    /// 8-block parallel AES-NI path. `first_rel_sector` is data-region relative.
    pub fn encrypt_area(&self, buf: &mut [u8], sector_size: usize, first_rel_sector: u64) {
        self.inner.encrypt_area(buf, sector_size, first_rel_sector);
    }

    /// Decrypt a contiguous buffer (inverse of [`encrypt_area`]).
    pub fn decrypt_area(&self, buf: &mut [u8], sector_size: usize, first_rel_sector: u64) {
        self.inner.decrypt_area(buf, sector_size, first_rel_sector);
    }
}

/// Expose AES-XTS as the generic [`VolumeCipher`] so it can be selected as one
/// of several vendor suites and stored as a trait object on the volume.
impl vck_common::VolumeCipher for AesXtsCipher {
    fn encrypt_sector(&self, rel_sector: u64, sector: &mut [u8]) {
        self.inner.encrypt_sector(rel_sector, sector);
    }
    fn decrypt_sector(&self, rel_sector: u64, sector: &mut [u8]) {
        self.inner.decrypt_sector(rel_sector, sector);
    }
    fn encrypt_area(&self, buf: &mut [u8], sector_size: usize, first_rel_sector: u64) {
        self.inner.encrypt_area(buf, sector_size, first_rel_sector);
    }
    fn decrypt_area(&self, buf: &mut [u8], sector_size: usize, first_rel_sector: u64) {
        self.inner.decrypt_area(buf, sector_size, first_rel_sector);
    }
}
