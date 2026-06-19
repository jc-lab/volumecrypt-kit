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
//!
//! # Performance
//!
//! All sectors are processed through an 8-block parallel XTS path that keeps 8
//! independent AES operations in flight simultaneously. On x86-64 with AES-NI
//! (detected at runtime by the `aes` crate) this saturates the throughput
//! pipeline (~1 cycle per 16-byte block) instead of being latency-bound
//! (~7 cycles per block for AES-256). Sectors are always a multiple of 16 bytes
//! (512, 4096, …) so ciphertext stealing never applies.
//!
//! # Kernel stack safety
//!
//! The driver runs this crypto on a constrained kernel stack (a system-thread
//! stack of ~24 KiB, and an IOCTL callout stack of 32 KiB). The crate is built
//! for the driver WITHOUT `-C target-feature=+aes`, so the `aes` crate's
//! fully-unrolled AES-NI `encrypt8`/`decrypt8` stay behind a runtime-dispatch
//! call boundary instead of being inlined into (and ballooning the frames of)
//! the deep storage/metadata call chain. The per-sector entry points are
//! additionally marked `#[inline(never)]` so their AES frames can never combine
//! with a caller's frame. (A prior build with `+aes` inlined the unrolled AES
//! into the IOCTL path and double-faulted on stack overflow.)

use alloc::boxed::Box;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes256, Block};

use crate::{
    types::{VolumeCipher, VolumeCipherSupplier},
    VckError, VckResult,
};

/// Number of AES-XTS blocks processed in one parallel batch.
/// Matches the AES-NI backend's `ParBlocks = 8`, filling the 7-cycle pipeline.
const BATCH: usize = 8;

pub struct XtsVolumeCipher {
    /// Data cipher for the AES-XTS payload blocks.
    cipher_1: Aes256,
    /// Tweak cipher (initial tweak = AES_K2(sector_number)).
    cipher_2: Aes256,
}

impl VolumeCipher for XtsVolumeCipher {
    fn encrypt_sector(&self, rel_sector: u64, sector: &mut [u8]) {
        XtsVolumeCipher::encrypt_sector(self, rel_sector, sector)
    }
    fn decrypt_sector(&self, rel_sector: u64, sector: &mut [u8]) {
        XtsVolumeCipher::decrypt_sector(self, rel_sector, sector)
    }
    fn encrypt_area(&self, buf: &mut [u8], sector_size: usize, first_rel_sector: u64) {
        XtsVolumeCipher::encrypt_area(self, buf, sector_size, first_rel_sector)
    }
    fn decrypt_area(&self, buf: &mut [u8], sector_size: usize, first_rel_sector: u64) {
        XtsVolumeCipher::decrypt_area(self, buf, sector_size, first_rel_sector)
    }
    // `destroy` uses the default no-op: `Aes256` does not expose its key-schedule
    // bytes for manual zeroization without the `zeroize` feature. Callers that
    // need guaranteed zeroization should use a custom `VolumeCipherSupplier` that
    // wraps key material in a `Zeroizing<[u8; 32]>` and re-derives per burst.
}

/// Default [`VolumeCipherSupplier`] for volumes that store AES-256-XTS key
/// material in ordinary (non-protected) memory.
///
/// Reconstructs the AES key schedule on each
/// [`get_cipher`](VolumeCipherSupplier::get_cipher) call.  The cost is one AES
/// key expansion (~480 bytes of computation) per I/O burst — negligible
/// compared with the I/O itself and bounded to once per [`MAX_IRP_BURST`] IRPs.
///
/// For RAM-encryption, implement [`VolumeCipherSupplier`] directly: derive the
/// key from protected storage on each call and override [`VolumeCipher::destroy`]
/// to zeroize it.
pub struct StaticCipherSupplier {
    key1: [u8; 32],
    key2: [u8; 32],
}

impl StaticCipherSupplier {
    pub fn new(key1: [u8; 32], key2: [u8; 32]) -> Self {
        Self { key1, key2 }
    }
}

impl VolumeCipherSupplier for StaticCipherSupplier {
    fn get_cipher(&self) -> Option<Box<dyn VolumeCipher>> {
        XtsVolumeCipher::new(&self.key1, &self.key2)
            .ok()
            .map(|c| Box::new(c) as Box<dyn VolumeCipher>)
    }
}

/// GF(2^128) multiplication by the primitive element alpha in the XTS field
/// (little-endian byte order, primitive polynomial x^128 + x^7 + x^2 + x + 1).
#[inline(always)]
fn gf128_mul(t: Block) -> Block {
    let lo = u64::from_le_bytes(t[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(t[8..].try_into().unwrap());
    let carry = if hi >> 63 != 0 { 0x87u64 } else { 0u64 };
    let mut out = Block::default();
    out[..8].copy_from_slice(&((lo << 1) ^ carry).to_le_bytes());
    out[8..].copy_from_slice(&((hi << 1) | (lo >> 63)).to_le_bytes());
    out
}

impl XtsVolumeCipher {
    pub fn new(key1: &[u8; 32], key2: &[u8; 32]) -> VckResult<Self> {
        let cipher_1 =
            Aes256::new_from_slice(key1).map_err(|_| VckError::CryptoFailed("invalid XTS key1"))?;
        let cipher_2 =
            Aes256::new_from_slice(key2).map_err(|_| VckError::CryptoFailed("invalid XTS key2"))?;
        Ok(Self { cipher_1, cipher_2 })
    }

    /// Encrypt one sector in place. `rel_sector` is data-region relative.
    pub fn encrypt_sector(&self, rel_sector: u64, sector: &mut [u8]) {
        self.encrypt_sector_inner(rel_sector, sector);
    }

    /// Decrypt one sector in place. `rel_sector` is data-region relative.
    pub fn decrypt_sector(&self, rel_sector: u64, sector: &mut [u8]) {
        self.decrypt_sector_inner(rel_sector, sector);
    }

    /// Encrypt a contiguous buffer of `sector_size`-byte sectors starting at
    /// data-region-relative sector `first_rel_sector`.
    pub fn encrypt_area(&self, buf: &mut [u8], sector_size: usize, first_rel_sector: u64) {
        for (si, sector) in buf.chunks_mut(sector_size).enumerate() {
            self.encrypt_sector_inner(first_rel_sector + si as u64, sector);
        }
    }

    /// Decrypt a contiguous buffer (inverse of [`encrypt_area`]).
    pub fn decrypt_area(&self, buf: &mut [u8], sector_size: usize, first_rel_sector: u64) {
        for (si, sector) in buf.chunks_mut(sector_size).enumerate() {
            self.decrypt_sector_inner(first_rel_sector + si as u64, sector);
        }
    }

    /// `#[inline(never)]` bounds this function's (AES-heavy) stack frame so it
    /// cannot merge with a deep caller's frame on the kernel stack.
    #[inline(never)]
    fn encrypt_sector_inner(&self, rel_sector: u64, sector: &mut [u8]) {
        // T_0 = AES_K2(sector_number as 128-bit little-endian)
        let mut tw: Block = (rel_sector as u128).to_le_bytes().into();
        self.cipher_2.encrypt_block(&mut tw);

        let n = sector.len() / 16;
        let mut off = 0;

        // 8-block parallel path: all 8 AES operations are independent so the
        // CPU can keep the AES-NI units fully pipelined.
        while off + BATCH <= n {
            let mut ts = [Block::default(); BATCH];
            ts[0] = tw;
            for i in 1..BATCH {
                ts[i] = gf128_mul(ts[i - 1]);
            }
            tw = gf128_mul(ts[BATCH - 1]);

            let mut batch = [Block::default(); BATCH];
            for i in 0..BATCH {
                let src = &sector[(off + i) * 16..(off + i + 1) * 16];
                for j in 0..16 {
                    batch[i][j] = src[j] ^ ts[i][j];
                }
            }
            self.cipher_1.encrypt_blocks(&mut batch);
            for i in 0..BATCH {
                let dst = &mut sector[(off + i) * 16..(off + i + 1) * 16];
                for j in 0..16 {
                    dst[j] = batch[i][j] ^ ts[i][j];
                }
            }
            off += BATCH;
        }

        // Scalar tail for sectors whose block count is not a multiple of BATCH.
        while off < n {
            let block = &mut sector[off * 16..(off + 1) * 16];
            for j in 0..16 {
                block[j] ^= tw[j];
            }
            let mut ga: Block = Block::try_from(&block[..]).unwrap();
            self.cipher_1.encrypt_block(&mut ga);
            block.copy_from_slice(&ga);
            for j in 0..16 {
                block[j] ^= tw[j];
            }
            tw = gf128_mul(tw);
            off += 1;
        }
    }

    #[inline(never)]
    fn decrypt_sector_inner(&self, rel_sector: u64, sector: &mut [u8]) {
        // Tweak is always encrypted with K2 (even during decryption).
        let mut tw: Block = (rel_sector as u128).to_le_bytes().into();
        self.cipher_2.encrypt_block(&mut tw);

        let n = sector.len() / 16;
        let mut off = 0;

        while off + BATCH <= n {
            let mut ts = [Block::default(); BATCH];
            ts[0] = tw;
            for i in 1..BATCH {
                ts[i] = gf128_mul(ts[i - 1]);
            }
            tw = gf128_mul(ts[BATCH - 1]);

            let mut batch = [Block::default(); BATCH];
            for i in 0..BATCH {
                let src = &sector[(off + i) * 16..(off + i + 1) * 16];
                for j in 0..16 {
                    batch[i][j] = src[j] ^ ts[i][j];
                }
            }
            self.cipher_1.decrypt_blocks(&mut batch);
            for i in 0..BATCH {
                let dst = &mut sector[(off + i) * 16..(off + i + 1) * 16];
                for j in 0..16 {
                    dst[j] = batch[i][j] ^ ts[i][j];
                }
            }
            off += BATCH;
        }

        while off < n {
            let block = &mut sector[off * 16..(off + 1) * 16];
            for j in 0..16 {
                block[j] ^= tw[j];
            }
            let mut ga: Block = Block::try_from(&block[..]).unwrap();
            self.cipher_1.decrypt_block(&mut ga);
            block.copy_from_slice(&ga);
            for j in 0..16 {
                block[j] ^= tw[j];
            }
            tw = gf128_mul(tw);
            off += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    // Reference implementation for cross-checking standards compliance.
    use xts_mode::{get_tweak_default, Xts128};

    const KEY1: [u8; 32] = [0x11; 32];
    const KEY2: [u8; 32] = [0x22; 32];

    /// Build the `xts-mode` reference cipher for the same key pair.
    fn reference() -> Xts128<Aes256> {
        let c1 = Aes256::new_from_slice(&KEY1).unwrap();
        let c2 = Aes256::new_from_slice(&KEY2).unwrap();
        Xts128::new(c1, c2)
    }

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

    /// Our parallel path must produce byte-identical ciphertext to the standard
    /// `xts-mode` implementation (data-region-relative sector as the tweak).
    #[test]
    fn matches_xts_mode_reference() {
        let c = XtsVolumeCipher::new(&KEY1, &KEY2).unwrap();
        let xts = reference();
        let sector_size = 512usize;
        let first = 7u64;
        let plain: Vec<u8> = (0..sector_size * 3).map(|i| (i * 7) as u8).collect();

        let mut ours = plain.clone();
        c.encrypt_area(&mut ours, sector_size, first);

        let mut refer = plain.clone();
        for s in 0..3u64 {
            let start = s as usize * sector_size;
            xts.encrypt_sector(
                &mut refer[start..start + sector_size],
                get_tweak_default((first + s) as u128),
            );
        }
        assert_eq!(ours, refer, "parallel XTS must match xts-mode reference");

        c.decrypt_area(&mut ours, sector_size, first);
        assert_eq!(ours, plain);
    }

    /// Round-trip with a sector size whose block count is not a multiple of
    /// BATCH (64 bytes = 4 blocks < 8) exercises the scalar tail.
    #[test]
    fn small_sector_roundtrip() {
        let c = XtsVolumeCipher::new(&KEY1, &KEY2).unwrap();
        let sector_size = 64usize;
        let plain: Vec<u8> = (0..sector_size * 5).map(|i| i as u8).collect();
        let mut buf = plain.clone();
        c.encrypt_area(&mut buf, sector_size, 0);
        assert_ne!(buf, plain);
        c.decrypt_area(&mut buf, sector_size, 0);
        assert_eq!(buf, plain);
    }
}
