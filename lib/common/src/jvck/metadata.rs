// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! JVCK Metadata block (fixed 512 bytes) parsing/encoding and key derivation.
//!
//! All integers are little-endian. The `Header CRC32` covers offsets 0..=507.
//! `EncryptedMetadata` is AES-256-CBC (no padding), 128 bytes.
//!
//! A 16-byte random `salt` (plaintext, offset 48) is mixed into the key
//! derivation (`HKDF salt = Volume ID ‖ salt`) and is regenerated on every
//! re-encode, so the AES-CBC key+IV are never reused across writes (the inner
//! plaintext is mostly constant, which would otherwise leak via identical
//! leading ciphertext blocks). The 192-byte `Vendor Specific Reserved` area
//! (offset 316) is available for vendor-defined parameters.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use crc::{Crc, CRC_32_ISO_HDLC};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

use crate::{types::Guid, VckError, VckResult};

type HmacSha256 = Hmac<Sha256>;

pub const JVCK_SIGNATURE: [u8; 4] = *b"JVCK";

/// Fixed size of the Metadata block (the part that carries the on-disk header
/// fields). Vendor-specific data lives outside this block.
pub const METADATA_BLOCK_SIZE: usize = 512;
pub const ENCRYPTED_METADATA_SIZE: usize = 128;
pub const HMAC_SIZE: usize = 32;
/// Per-write random salt mixed into the key-derivation HKDF salt.
pub const SALT_SIZE: usize = 16;
/// Vendor-defined area before the Header CRC32 (zeroed by the default suite).
pub const VENDOR_RESERVED_SIZE: usize = 192;

/// HKDF-SHA256 info labels.
pub const INFO_MAC: &[u8] = b"EncryptedMetadata:MAC";
pub const INFO_ENC: &[u8] = b"EncryptedMetadata:ENC";
pub const INFO_IV: &[u8] = b"EncryptedMetadata:IV";

/// Keys derived from the VMK, the (plaintext) Volume ID, and the per-write
/// salt. Zeroized on drop so the derived AES/HMAC material does not linger.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub mac_key: [u8; 32],
    pub enc_key: [u8; 32],
    pub enc_iv: [u8; 16],
}

/// Derive the MAC/ENC/IV material:
/// `HKDF_SHA256(salt = Volume ID ‖ salt, ikm = VMK, info = label)`.
///
/// The per-write `salt` (regenerated on every re-encode) makes all three keys
/// fresh per write, so the AES-CBC key+IV are never reused for the same volume.
pub fn derive_keys(volume_id: &[u8; 16], salt: &[u8; SALT_SIZE], vmk: &[u8]) -> DerivedKeys {
    let mut hkdf_salt = [0u8; 16 + SALT_SIZE];
    hkdf_salt[..16].copy_from_slice(volume_id);
    hkdf_salt[16..].copy_from_slice(salt);
    let hk = Hkdf::<Sha256>::new(Some(&hkdf_salt), vmk);
    let mut keys = DerivedKeys {
        mac_key: [0u8; 32],
        enc_key: [0u8; 32],
        enc_iv: [0u8; 16],
    };
    // expand() only fails when the output length exceeds 255*HashLen, which is
    // impossible for 32/16-byte outputs, so these cannot error in practice.
    hk.expand(INFO_MAC, &mut keys.mac_key)
        .expect("HKDF MAC output length is valid");
    hk.expand(INFO_ENC, &mut keys.enc_key)
        .expect("HKDF ENC output length is valid");
    hk.expand(INFO_IV, &mut keys.enc_iv)
        .expect("HKDF IV output length is valid");
    keys
}

// --- EncryptedMetadata field offsets (within the 128-byte plaintext) ---
pub const EM_OFF_SIGNATURE: usize = 0;
pub const EM_OFF_MUST_ZERO: usize = 4;
pub const EM_OFF_ENCRYPTED_OFFSET: usize = 16;
pub const EM_OFF_FVEK_KEY1: usize = 32;
pub const EM_OFF_FVEK_KEY2: usize = 64;

/// Plaintext header fields of a Metadata block.
///
/// These live outside the encrypted blob, so parsing them needs neither the VMK
/// nor any decryption. The on-disk layout (`metadata_size`, replica counts) is
/// recovered from here without ever touching the sensitive key material.
#[derive(Debug, Clone)]
pub struct JvckHeader {
    pub vendor_id: u64,
    pub metadata_version: u16,
    pub vendor_version: u16,
    /// Replica region size (vendor data included).
    pub metadata_size: u32,
    pub sector_size: u32,
    pub header_replica_count: u8,
    pub footer_replica_count: u8,
    pub volume_id: [u8; 16],
}

/// Sensitive FVEK material decrypted from the EncryptedMetadata blob.
///
/// Zeroized on drop so the plaintext volume keys are wiped as soon as the value
/// goes out of scope. Decrypt only when the keys are actually needed (building
/// the cipher / re-encoding metadata) and drop the value promptly afterwards.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct JvckSecrets {
    pub fvek_key1: [u8; 32],
    pub fvek_key2: [u8; 32],
}

// --- Metadata block field offsets ---
pub const OFF_SIGNATURE: usize = 0;
pub const OFF_VENDOR_ID: usize = 4;
pub const OFF_METADATA_VERSION: usize = 12;
pub const OFF_VENDOR_VERSION: usize = 14;
pub const OFF_METADATA_SIZE: usize = 16;
pub const OFF_SECTOR_SIZE: usize = 20;
pub const OFF_HEADER_COUNT: usize = 24;
pub const OFF_FOOTER_COUNT: usize = 25;
pub const OFF_VOLUME_ID: usize = 32;
pub const OFF_SALT: usize = 48;
pub const OFF_ENCRYPTED_METADATA: usize = 64;
pub const OFF_HMAC: usize = 192;
// Aligned tail: 224..304 Reserved (zero); 304..496 Vendor Specific Reserved (192,
// 16-byte aligned); 496..508 Reserved (zero, 12); 508..512 Header CRC32.
pub const OFF_VENDOR_RESERVED: usize = 304;
pub const OFF_CRC32: usize = 508;
/// CRC32 covers bytes [0, CRC_COVERAGE_END).
pub const CRC_COVERAGE_END: usize = 508;

/// Read a little-endian integer from a fixed offset. Panics only on a static
/// slice-length bug (offsets are compile-time constants within the 512 block).
fn le_u16(block: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(block[off..off + 2].try_into().unwrap())
}
fn le_u32(block: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(block[off..off + 4].try_into().unwrap())
}
fn le_u64(block: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(block[off..off + 8].try_into().unwrap())
}

impl JvckHeader {
    /// Parse the plaintext header fields of a Metadata block.
    ///
    /// Verifies the `JVCK` signature and Header CRC32 over [0,508) but does NOT
    /// touch the encrypted blob, so no key material is decrypted. Use this to
    /// recover the on-disk layout (`metadata_size`, replica counts) cheaply and
    /// without the VMK.
    pub fn parse(block: &[u8]) -> VckResult<Self> {
        verify_crc(block)?;
        let block = &block[..METADATA_BLOCK_SIZE];
        Ok(Self {
            vendor_id: le_u64(block, OFF_VENDOR_ID),
            metadata_version: le_u16(block, OFF_METADATA_VERSION),
            vendor_version: le_u16(block, OFF_VENDOR_VERSION),
            metadata_size: le_u32(block, OFF_METADATA_SIZE),
            sector_size: le_u32(block, OFF_SECTOR_SIZE),
            header_replica_count: block[OFF_HEADER_COUNT],
            footer_replica_count: block[OFF_FOOTER_COUNT],
            volume_id: block[OFF_VOLUME_ID..OFF_VOLUME_ID + 16].try_into().unwrap(),
        })
    }

    /// Serialize this header plus the (sensitive) `secrets` and `encrypted_offset`
    /// into a 512-byte block, encrypting the inner payload and computing HMAC +
    /// CRC32. The transient EncryptedMetadata plaintext is zeroized afterwards.
    pub fn encode(
        &self,
        secrets: &JvckSecrets,
        encrypted_offset: u64,
        salt: &[u8; SALT_SIZE],
        vmk: &[u8],
        out: &mut [u8; METADATA_BLOCK_SIZE],
    ) -> VckResult<()> {
        out.fill(0);
        out[OFF_SIGNATURE..OFF_SIGNATURE + 4].copy_from_slice(&JVCK_SIGNATURE);
        out[OFF_VENDOR_ID..OFF_VENDOR_ID + 8].copy_from_slice(&self.vendor_id.to_le_bytes());
        out[OFF_METADATA_VERSION..OFF_METADATA_VERSION + 2]
            .copy_from_slice(&self.metadata_version.to_le_bytes());
        out[OFF_VENDOR_VERSION..OFF_VENDOR_VERSION + 2]
            .copy_from_slice(&self.vendor_version.to_le_bytes());
        out[OFF_METADATA_SIZE..OFF_METADATA_SIZE + 4]
            .copy_from_slice(&self.metadata_size.to_le_bytes());
        out[OFF_SECTOR_SIZE..OFF_SECTOR_SIZE + 4].copy_from_slice(&self.sector_size.to_le_bytes());
        out[OFF_HEADER_COUNT] = self.header_replica_count;
        out[OFF_FOOTER_COUNT] = self.footer_replica_count;
        out[OFF_VOLUME_ID..OFF_VOLUME_ID + 16].copy_from_slice(&self.volume_id);
        // Per-write salt (plaintext): read back at decrypt time to re-derive keys.
        out[OFF_SALT..OFF_SALT + SALT_SIZE].copy_from_slice(salt);

        // Build the 128-byte EncryptedMetadata plaintext (holds the FVEK), then
        // zeroize it before returning so the keys do not linger on the stack.
        let mut plain = [0u8; ENCRYPTED_METADATA_SIZE];
        plain[EM_OFF_SIGNATURE..EM_OFF_SIGNATURE + 4].copy_from_slice(&JVCK_SIGNATURE);
        plain[EM_OFF_ENCRYPTED_OFFSET..EM_OFF_ENCRYPTED_OFFSET + 8]
            .copy_from_slice(&encrypted_offset.to_le_bytes());
        plain[EM_OFF_FVEK_KEY1..EM_OFF_FVEK_KEY1 + 32].copy_from_slice(&secrets.fvek_key1);
        plain[EM_OFF_FVEK_KEY2..EM_OFF_FVEK_KEY2 + 32].copy_from_slice(&secrets.fvek_key2);

        let keys = derive_keys(&self.volume_id, salt, vmk);
        let result = (|| {
            let enc = Encryptor::<Aes256>::new_from_slices(&keys.enc_key, &keys.enc_iv)
                .map_err(|_| VckError::CryptoFailed("invalid ENC key/iv length"))?;
            enc.encrypt_padded_mut::<NoPadding>(&mut plain, ENCRYPTED_METADATA_SIZE)
                .map_err(|_| VckError::CryptoFailed("EncryptedMetadata CBC encrypt failed"))?;
            out[OFF_ENCRYPTED_METADATA..OFF_ENCRYPTED_METADATA + ENCRYPTED_METADATA_SIZE]
                .copy_from_slice(&plain);

            // HMAC over the (now encrypted) blob.
            let mut mac = HmacSha256::new_from_slice(&keys.mac_key)
                .map_err(|_| VckError::CryptoFailed("invalid HMAC key length"))?;
            mac.update(
                &out[OFF_ENCRYPTED_METADATA..OFF_ENCRYPTED_METADATA + ENCRYPTED_METADATA_SIZE],
            );
            let tag = mac.finalize().into_bytes();
            out[OFF_HMAC..OFF_HMAC + HMAC_SIZE].copy_from_slice(&tag);

            // Header CRC32 over [0, 508).
            let crc = CRC32.checksum(&out[0..CRC_COVERAGE_END]);
            out[OFF_CRC32..OFF_CRC32 + 4].copy_from_slice(&crc.to_le_bytes());
            Ok(())
        })();
        plain.zeroize();
        result
    }

    pub fn volume_guid(&self) -> Guid {
        Guid::from_bytes(self.volume_id)
    }
}

/// Verify only the plaintext signature + Header CRC32 (used while scanning for a
/// replica before the VMK is applied).
pub fn verify_crc(block: &[u8]) -> VckResult<()> {
    if block.len() < METADATA_BLOCK_SIZE {
        return Err(VckError::SizeMismatch {
            expected: METADATA_BLOCK_SIZE,
            actual: block.len(),
        });
    }
    if block[OFF_SIGNATURE..OFF_SIGNATURE + 4] != JVCK_SIGNATURE {
        return Err(VckError::SignatureMismatch);
    }
    let stored = le_u32(block, OFF_CRC32);
    if CRC32.checksum(&block[0..CRC_COVERAGE_END]) != stored {
        return Err(VckError::ChecksumMismatch);
    }
    Ok(())
}

/// Authenticate (HMAC) and AES-256-CBC decrypt the EncryptedMetadata payload.
///
/// Verifies the Header CRC32, the HMAC (so a wrong VMK is rejected before any
/// decryption), and the inner `JVCK` signature + zero field. The transient
/// plaintext buffer is zeroized before returning; only the non-sensitive
/// `encrypted_offset` and the zeroize-on-drop `JvckSecrets` survive.
pub fn decrypt_payload(block: &[u8], vmk: &[u8]) -> VckResult<(u64, JvckSecrets)> {
    verify_crc(block)?;
    let block = &block[..METADATA_BLOCK_SIZE];

    let volume_id: [u8; 16] = block[OFF_VOLUME_ID..OFF_VOLUME_ID + 16].try_into().unwrap();
    let salt: [u8; SALT_SIZE] = block[OFF_SALT..OFF_SALT + SALT_SIZE].try_into().unwrap();
    let keys = derive_keys(&volume_id, &salt, vmk);

    // Authenticate the encrypted blob before decrypting.
    let enc = &block[OFF_ENCRYPTED_METADATA..OFF_ENCRYPTED_METADATA + ENCRYPTED_METADATA_SIZE];
    let stored_hmac = &block[OFF_HMAC..OFF_HMAC + HMAC_SIZE];
    let mut mac = HmacSha256::new_from_slice(&keys.mac_key)
        .map_err(|_| VckError::CryptoFailed("invalid HMAC key length"))?;
    mac.update(enc);
    mac.verify_slice(stored_hmac)
        .map_err(|_| VckError::ValidationFailed("EncryptedMetadata HMAC mismatch"))?;

    // AES-256-CBC (no padding) decrypt into a buffer we zeroize on the way out.
    let mut buf = [0u8; ENCRYPTED_METADATA_SIZE];
    buf.copy_from_slice(enc);
    let parsed = (|| {
        let dec = Decryptor::<Aes256>::new_from_slices(&keys.enc_key, &keys.enc_iv)
            .map_err(|_| VckError::CryptoFailed("invalid ENC key/iv length"))?;
        let plain = dec
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .map_err(|_| VckError::CryptoFailed("EncryptedMetadata CBC decrypt failed"))?;

        // Verify the inner signature + zero field (wrong VMK -> garbage here).
        if plain[EM_OFF_SIGNATURE..EM_OFF_SIGNATURE + 4] != JVCK_SIGNATURE {
            return Err(VckError::ValidationFailed("inner JVCK signature mismatch"));
        }
        if plain[EM_OFF_MUST_ZERO..EM_OFF_MUST_ZERO + 12] != [0u8; 12] {
            return Err(VckError::ValidationFailed("inner must-zero field not zero"));
        }

        let mut secrets = JvckSecrets {
            fvek_key1: [0u8; 32],
            fvek_key2: [0u8; 32],
        };
        secrets
            .fvek_key1
            .copy_from_slice(&plain[EM_OFF_FVEK_KEY1..EM_OFF_FVEK_KEY1 + 32]);
        secrets
            .fvek_key2
            .copy_from_slice(&plain[EM_OFF_FVEK_KEY2..EM_OFF_FVEK_KEY2 + 32]);
        Ok((le_u64(plain, EM_OFF_ENCRYPTED_OFFSET), secrets))
    })();
    buf.zeroize();
    parsed
}

/// Decrypt only to read `encrypted_offset`; the FVEK material is zeroized
/// immediately (the returned `JvckSecrets` is dropped here). Use this on the
/// recovery scan, which must not retain the volume keys.
pub fn read_encrypted_offset(block: &[u8], vmk: &[u8]) -> VckResult<u64> {
    let (encrypted_offset, _secrets) = decrypt_payload(block, vmk)?;
    Ok(encrypted_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed salt so encode output is deterministic in tests.
    const TEST_SALT: [u8; SALT_SIZE] = [0x5a; SALT_SIZE];

    fn sample_header() -> JvckHeader {
        JvckHeader {
            vendor_id: 0x0102_0304_0506_0708,
            metadata_version: 1,
            vendor_version: 7,
            metadata_size: 128 * 1024,
            sector_size: 512,
            header_replica_count: 0,
            footer_replica_count: 2,
            volume_id: [0x11; 16],
        }
    }

    fn sample_secrets() -> JvckSecrets {
        JvckSecrets {
            fvek_key1: [0xAA; 32],
            fvek_key2: [0xBB; 32],
        }
    }

    /// Encode the sample (header + secrets + offset) into a fresh block.
    fn encode_sample(vmk: &[u8], offset: u64) -> [u8; METADATA_BLOCK_SIZE] {
        let mut block = [0u8; METADATA_BLOCK_SIZE];
        sample_header()
            .encode(&sample_secrets(), offset, &TEST_SALT, vmk, &mut block)
            .unwrap();
        block
    }

    #[test]
    fn derive_keys_is_deterministic_and_label_separated() {
        let a = derive_keys(&[1u8; 16], &TEST_SALT, b"vmk-secret");
        let b = derive_keys(&[1u8; 16], &TEST_SALT, b"vmk-secret");
        assert_eq!(a.mac_key, b.mac_key);
        assert_eq!(a.enc_key, b.enc_key);
        assert_eq!(a.enc_iv, b.enc_iv);
        // Different labels must yield different material.
        assert_ne!(a.mac_key, a.enc_key);
        // Different Volume ID must change the output.
        let c = derive_keys(&[2u8; 16], &TEST_SALT, b"vmk-secret");
        assert_ne!(a.enc_key, c.enc_key);
        // Different salt must change the output (per-write freshness).
        let d = derive_keys(&[1u8; 16], &[0x11; SALT_SIZE], b"vmk-secret");
        assert_ne!(a.enc_key, d.enc_key);
        assert_ne!(a.enc_iv, d.enc_iv);
    }

    #[test]
    fn encode_parse_roundtrip() {
        let vmk = b"my-volume-master-key";
        let block = encode_sample(vmk, 4096);

        // Plaintext header parses without the VMK.
        let header = JvckHeader::parse(&block).unwrap();
        assert_eq!(header.vendor_id, 0x0102_0304_0506_0708);
        assert_eq!(header.metadata_size, 128 * 1024);
        assert_eq!(header.sector_size, 512);
        assert_eq!(header.footer_replica_count, 2);
        assert_eq!(header.volume_id, [0x11; 16]);

        // Secrets + offset require the VMK.
        let (offset, secrets) = decrypt_payload(&block, vmk).unwrap();
        assert_eq!(offset, 4096);
        assert_eq!(secrets.fvek_key1, [0xAA; 32]);
        assert_eq!(secrets.fvek_key2, [0xBB; 32]);

        // Offset-only path returns the same value.
        assert_eq!(read_encrypted_offset(&block, vmk).unwrap(), 4096);
    }

    #[test]
    fn parse_rejects_wrong_vmk() {
        let block = encode_sample(b"correct-vmk", 0);
        // Wrong VMK -> HMAC mismatch (CRC still valid). Header still parses.
        assert!(JvckHeader::parse(&block).is_ok());
        assert!(matches!(
            decrypt_payload(&block, b"wrong-vmk"),
            Err(VckError::ValidationFailed(_))
        ));
    }

    #[test]
    fn parse_rejects_corrupted_crc() {
        let mut block = encode_sample(b"vmk", 0);
        block[100] ^= 0xFF; // flip a covered byte
        assert!(matches!(
            JvckHeader::parse(&block),
            Err(VckError::ChecksumMismatch)
        ));
        assert!(matches!(
            decrypt_payload(&block, b"vmk"),
            Err(VckError::ChecksumMismatch)
        ));
    }

    #[test]
    fn parse_rejects_bad_signature() {
        let mut block = encode_sample(b"vmk", 0);
        block[0] = b'X';
        assert!(matches!(
            JvckHeader::parse(&block),
            Err(VckError::SignatureMismatch)
        ));
    }

    #[test]
    fn parse_rejects_short_block() {
        let short = [0u8; 64];
        assert!(matches!(
            JvckHeader::parse(&short),
            Err(VckError::SizeMismatch { .. })
        ));
    }

    /// Fixed cross-check vector shared with the Go SDK encoder (sdk/jvck_test.go).
    /// Both implementations must produce this exact 512-byte block, proving the
    /// on-disk format is byte-compatible across the two languages.
    fn cross_check_block() -> [u8; METADATA_BLOCK_SIZE] {
        let vmk = b"jvck-cross-check-vmk";
        let header = JvckHeader {
            vendor_id: 0,
            metadata_version: 1,
            vendor_version: 0,
            metadata_size: 131072,
            sector_size: 512,
            header_replica_count: 0,
            footer_replica_count: 2,
            volume_id: [
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ],
        };
        let secrets = JvckSecrets {
            fvek_key1: [0xA0; 32],
            fvek_key2: [0x0B; 32],
        };
        let mut block = [0u8; METADATA_BLOCK_SIZE];
        header
            .encode(&secrets, 12345, &TEST_SALT, vmk, &mut block)
            .unwrap();
        block
    }

    /// Golden 512-byte block for the cross-check vector. The Go SDK encoder
    /// (sdk/jvck_test.go) asserts the identical hex, so a divergence in either
    /// implementation's on-disk format fails a unit test in both repos.
    const CROSS_CHECK_HEX: &str = "4a56434b000000000000000001000000000002000002000000020000000000000102030405060708090a0b0c0d0e0f105a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a2596594092215a84c28c512040b89465b5013606c9597f80993d82ab7ed62de7b259177923c5ef67aac93ce844eea143fd524315ee5643556e076f10056cf8d0fcc73e43af3ce790249a042f0cdb4126c9f78e5b7c854745b21a67a672e1d20769aad3fdde489426a4de635e62cef042a1882b9b748c558df412234e9f8557732be236e87fba6a2265a5be53e8b778a960c389af50380dc8a62921672fd2627c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b17a9689";

    #[test]
    fn cross_check_vector_matches_golden() {
        let block = cross_check_block();
        let mut hex = String::new();
        for b in block {
            hex.push_str(&alloc::format!("{:02x}", b));
        }
        assert_eq!(hex, CROSS_CHECK_HEX);
    }
}
