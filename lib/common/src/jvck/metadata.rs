//! JVCK Metadata block (fixed 512 bytes) parsing/encoding and key derivation.
//!
//! All integers are little-endian. The `Header CRC32` covers offsets 0..=507.
//! `EncryptedMetadata` is AES-256-CBC (no padding), 128 bytes.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{types::Guid, VckError, VckResult};

type HmacSha256 = Hmac<Sha256>;

pub const JVCK_SIGNATURE: [u8; 4] = *b"JVCK";

/// Fixed size of the Metadata block (the part that carries the on-disk header
/// fields). Vendor-specific data lives outside this block.
pub const METADATA_BLOCK_SIZE: usize = 512;
pub const ENCRYPTED_METADATA_SIZE: usize = 128;
pub const HMAC_SIZE: usize = 32;

/// HKDF-SHA256 info labels.
pub const INFO_MAC: &[u8] = b"EncryptedMetadata:MAC";
pub const INFO_ENC: &[u8] = b"EncryptedMetadata:ENC";
pub const INFO_IV: &[u8] = b"EncryptedMetadata:IV";

/// Keys derived from the VMK and the (plaintext) Volume ID salt.
#[derive(Clone)]
pub struct DerivedKeys {
    pub mac_key: [u8; 32],
    pub enc_key: [u8; 32],
    pub enc_iv: [u8; 16],
}

/// Derive the MAC/ENC/IV material:
/// `HKDF_SHA256(salt = Volume ID, ikm = VMK, info = label)`.
pub fn derive_keys(volume_id: &[u8; 16], vmk: &[u8]) -> DerivedKeys {
    let hk = Hkdf::<Sha256>::new(Some(volume_id), vmk);
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

/// Decrypted inner payload of the Metadata block (128-byte EncryptedMetadata).
#[derive(Debug, Clone)]
pub struct EncryptedMetadata {
    pub encrypted_offset: u64,
    pub fvek_key1: [u8; 32],
    pub fvek_key2: [u8; 32],
}

// --- EncryptedMetadata field offsets (within the 128-byte plaintext) ---
pub const EM_OFF_SIGNATURE: usize = 0;
pub const EM_OFF_MUST_ZERO: usize = 4;
pub const EM_OFF_ENCRYPTED_OFFSET: usize = 16;
pub const EM_OFF_FVEK_KEY1: usize = 32;
pub const EM_OFF_FVEK_KEY2: usize = 64;

/// A parsed JVCK Metadata block. Header fields and the decrypted inner payload
/// are flattened for ergonomic access (`meta.fvek_key1`, `meta.encrypted_offset`).
#[derive(Debug, Clone)]
pub struct JvckMetadata {
    pub vendor_id: u64,
    pub metadata_version: u16,
    pub vendor_version: u16,
    /// Replica region size (vendor data included).
    pub metadata_size: u32,
    pub sector_size: u32,
    pub header_replica_count: u8,
    pub footer_replica_count: u8,
    pub volume_id: [u8; 16],
    // --- decrypted EncryptedMetadata fields ---
    pub encrypted_offset: u64,
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
pub const OFF_ENCRYPTED_METADATA: usize = 48;
pub const OFF_HMAC: usize = 176;
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

impl JvckMetadata {
    /// Parse and authenticate a 512-byte Metadata block using the VMK.
    ///
    /// Steps: verify `JVCK` signature, verify Header CRC32 over [0,508),
    /// derive keys, verify HMAC over the encrypted blob, AES-256-CBC decrypt,
    /// verify inner `JVCK` signature + zero field.
    pub fn parse(block: &[u8], vmk: &[u8]) -> VckResult<Self> {
        Self::verify_crc(block)?;
        let block = &block[..METADATA_BLOCK_SIZE];

        let volume_id: [u8; 16] = block[OFF_VOLUME_ID..OFF_VOLUME_ID + 16].try_into().unwrap();
        let keys = derive_keys(&volume_id, vmk);

        // Authenticate the encrypted blob before decrypting.
        let enc = &block[OFF_ENCRYPTED_METADATA..OFF_ENCRYPTED_METADATA + ENCRYPTED_METADATA_SIZE];
        let stored_hmac = &block[OFF_HMAC..OFF_HMAC + HMAC_SIZE];
        let mut mac = HmacSha256::new_from_slice(&keys.mac_key)
            .map_err(|_| VckError::CryptoFailed("invalid HMAC key length"))?;
        mac.update(enc);
        mac.verify_slice(stored_hmac)
            .map_err(|_| VckError::ValidationFailed("EncryptedMetadata HMAC mismatch"))?;

        // AES-256-CBC (no padding) decrypt.
        let mut buf = [0u8; ENCRYPTED_METADATA_SIZE];
        buf.copy_from_slice(enc);
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

        let mut fvek_key1 = [0u8; 32];
        fvek_key1.copy_from_slice(&plain[EM_OFF_FVEK_KEY1..EM_OFF_FVEK_KEY1 + 32]);
        let mut fvek_key2 = [0u8; 32];
        fvek_key2.copy_from_slice(&plain[EM_OFF_FVEK_KEY2..EM_OFF_FVEK_KEY2 + 32]);

        Ok(Self {
            vendor_id: le_u64(block, OFF_VENDOR_ID),
            metadata_version: le_u16(block, OFF_METADATA_VERSION),
            vendor_version: le_u16(block, OFF_VENDOR_VERSION),
            metadata_size: le_u32(block, OFF_METADATA_SIZE),
            sector_size: le_u32(block, OFF_SECTOR_SIZE),
            header_replica_count: block[OFF_HEADER_COUNT],
            footer_replica_count: block[OFF_FOOTER_COUNT],
            volume_id,
            encrypted_offset: le_u64(plain, EM_OFF_ENCRYPTED_OFFSET),
            fvek_key1,
            fvek_key2,
        })
    }

    /// Serialize this metadata into a 512-byte block, encrypting the inner
    /// payload and computing HMAC + CRC32.
    pub fn encode(&self, vmk: &[u8], out: &mut [u8; METADATA_BLOCK_SIZE]) -> VckResult<()> {
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

        // Build the 128-byte EncryptedMetadata plaintext.
        let mut plain = [0u8; ENCRYPTED_METADATA_SIZE];
        plain[EM_OFF_SIGNATURE..EM_OFF_SIGNATURE + 4].copy_from_slice(&JVCK_SIGNATURE);
        plain[EM_OFF_ENCRYPTED_OFFSET..EM_OFF_ENCRYPTED_OFFSET + 8]
            .copy_from_slice(&self.encrypted_offset.to_le_bytes());
        plain[EM_OFF_FVEK_KEY1..EM_OFF_FVEK_KEY1 + 32].copy_from_slice(&self.fvek_key1);
        plain[EM_OFF_FVEK_KEY2..EM_OFF_FVEK_KEY2 + 32].copy_from_slice(&self.fvek_key2);

        let keys = derive_keys(&self.volume_id, vmk);
        let enc = Encryptor::<Aes256>::new_from_slices(&keys.enc_key, &keys.enc_iv)
            .map_err(|_| VckError::CryptoFailed("invalid ENC key/iv length"))?;
        enc.encrypt_padded_mut::<NoPadding>(&mut plain, ENCRYPTED_METADATA_SIZE)
            .map_err(|_| VckError::CryptoFailed("EncryptedMetadata CBC encrypt failed"))?;
        out[OFF_ENCRYPTED_METADATA..OFF_ENCRYPTED_METADATA + ENCRYPTED_METADATA_SIZE]
            .copy_from_slice(&plain);

        // HMAC over the (now encrypted) blob.
        let mut mac = HmacSha256::new_from_slice(&keys.mac_key)
            .map_err(|_| VckError::CryptoFailed("invalid HMAC key length"))?;
        mac.update(&out[OFF_ENCRYPTED_METADATA..OFF_ENCRYPTED_METADATA + ENCRYPTED_METADATA_SIZE]);
        let tag = mac.finalize().into_bytes();
        out[OFF_HMAC..OFF_HMAC + HMAC_SIZE].copy_from_slice(&tag);

        // Header CRC32 over [0, 508).
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&out[0..CRC_COVERAGE_END]);
        out[OFF_CRC32..OFF_CRC32 + 4].copy_from_slice(&hasher.finalize().to_le_bytes());
        Ok(())
    }

    /// Verify only the plaintext signature + Header CRC32 (used while scanning
    /// for a replica before the VMK is applied).
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
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&block[0..CRC_COVERAGE_END]);
        if hasher.finalize() != stored {
            return Err(VckError::ChecksumMismatch);
        }
        Ok(())
    }

    pub fn volume_guid(&self) -> Guid {
        Guid::from_bytes(self.volume_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> JvckMetadata {
        JvckMetadata {
            vendor_id: 0x0102_0304_0506_0708,
            metadata_version: 1,
            vendor_version: 7,
            metadata_size: 128 * 1024,
            sector_size: 512,
            header_replica_count: 0,
            footer_replica_count: 2,
            volume_id: [0x11; 16],
            encrypted_offset: 4096,
            fvek_key1: [0xAA; 32],
            fvek_key2: [0xBB; 32],
        }
    }

    #[test]
    fn derive_keys_is_deterministic_and_label_separated() {
        let a = derive_keys(&[1u8; 16], b"vmk-secret");
        let b = derive_keys(&[1u8; 16], b"vmk-secret");
        assert_eq!(a.mac_key, b.mac_key);
        assert_eq!(a.enc_key, b.enc_key);
        assert_eq!(a.enc_iv, b.enc_iv);
        // Different labels must yield different material.
        assert_ne!(a.mac_key, a.enc_key);
        // Different salt (Volume ID) must change the output.
        let c = derive_keys(&[2u8; 16], b"vmk-secret");
        assert_ne!(a.enc_key, c.enc_key);
    }

    #[test]
    fn encode_parse_roundtrip() {
        let vmk = b"my-volume-master-key";
        let meta = sample();
        let mut block = [0u8; METADATA_BLOCK_SIZE];
        meta.encode(vmk, &mut block).unwrap();

        let parsed = JvckMetadata::parse(&block, vmk).unwrap();
        assert_eq!(parsed.vendor_id, meta.vendor_id);
        assert_eq!(parsed.metadata_size, meta.metadata_size);
        assert_eq!(parsed.sector_size, meta.sector_size);
        assert_eq!(parsed.footer_replica_count, 2);
        assert_eq!(parsed.volume_id, meta.volume_id);
        assert_eq!(parsed.encrypted_offset, 4096);
        assert_eq!(parsed.fvek_key1, meta.fvek_key1);
        assert_eq!(parsed.fvek_key2, meta.fvek_key2);
    }

    #[test]
    fn parse_rejects_wrong_vmk() {
        let meta = sample();
        let mut block = [0u8; METADATA_BLOCK_SIZE];
        meta.encode(b"correct-vmk", &mut block).unwrap();
        // Wrong VMK -> HMAC mismatch (CRC still valid).
        let err = JvckMetadata::parse(&block, b"wrong-vmk").unwrap_err();
        assert!(matches!(err, VckError::ValidationFailed(_)));
    }

    #[test]
    fn parse_rejects_corrupted_crc() {
        let meta = sample();
        let mut block = [0u8; METADATA_BLOCK_SIZE];
        meta.encode(b"vmk", &mut block).unwrap();
        block[100] ^= 0xFF; // flip a covered byte
        let err = JvckMetadata::parse(&block, b"vmk").unwrap_err();
        assert!(matches!(err, VckError::ChecksumMismatch));
    }

    #[test]
    fn parse_rejects_bad_signature() {
        let mut block = [0u8; METADATA_BLOCK_SIZE];
        sample().encode(b"vmk", &mut block).unwrap();
        block[0] = b'X';
        assert!(matches!(
            JvckMetadata::parse(&block, b"vmk"),
            Err(VckError::SignatureMismatch)
        ));
    }

    #[test]
    fn parse_rejects_short_block() {
        let short = [0u8; 64];
        assert!(matches!(
            JvckMetadata::parse(&short, b"vmk"),
            Err(VckError::SizeMismatch { .. })
        ));
    }
}
