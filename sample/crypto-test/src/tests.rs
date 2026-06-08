//! In-kernel crypto self-tests. Each `check_*` returns whether it passed.

#[derive(Debug, Clone, Copy, Default)]
pub struct Report {
    pub passed: u32,
    pub failed: u32,
}

impl Report {
    fn record(&mut self, ok: bool) {
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
    }
}

pub fn run_all() -> Report {
    let mut report = Report::default();
    report.record(check_hkdf_derivation());
    report.record(check_header_crc32());
    report.record(check_encrypted_metadata_roundtrip());
    report.record(check_aes_xts_sector_roundtrip());
    report
}

/// HKDF-SHA256 derivation matches known-answer vectors for MAC/ENC/IV labels.
fn check_hkdf_derivation() -> bool {
    // TODO(crypto-test): compare jvck::metadata::derive_keys against KATs.
    false
}

/// Header CRC32 over [0,508) round-trips.
fn check_header_crc32() -> bool {
    // TODO(crypto-test): build a block, verify JvckMetadata::verify_crc.
    false
}

/// EncryptedMetadata encrypt(encode) -> decrypt(parse) recovers FVEK + offset.
fn check_encrypted_metadata_roundtrip() -> bool {
    // TODO(crypto-test): JvckMetadata::encode then parse with the same VMK.
    false
}

/// AES-XTS encrypt then decrypt a sector returns the original plaintext.
fn check_aes_xts_sector_roundtrip() -> bool {
    // TODO(crypto-test): vck_driver::crypto::AesXtsCipher encrypt/decrypt.
    false
}
