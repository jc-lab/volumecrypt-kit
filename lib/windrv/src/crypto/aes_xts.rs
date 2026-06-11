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
}
