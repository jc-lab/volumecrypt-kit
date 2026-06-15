// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Pluggable cryptographic randomness source.
//!
//! `lib/common` is `no_std` and has no RNG of its own. The JVCK metadata store
//! needs a fresh random salt every time it (re)encodes the EncryptedMetadata
//! blob (see `jvck::metadata`), so the integrator installs a platform RNG once
//! at startup:
//!
//! - kernel driver: a `BCryptGenRandom`-backed source, installed in `DriverEntry`;
//! - host tests/tooling: any deterministic or `std`-backed source.
//!
//! The loader never re-encodes metadata (its volume is read-only), so it does
//! not need to install a source.

use crate::{VckError, VckResult};

/// A cryptographically secure randomness source.
pub trait RandomSource: Send + Sync {
    /// Fill `buf` with random bytes, or return an error if randomness is
    /// unavailable.
    fn fill(&self, buf: &mut [u8]) -> VckResult<()>;
}

static RNG: spin::Once<&'static dyn RandomSource> = spin::Once::new();

/// Install the process-wide randomness source. Idempotent — only the first call
/// takes effect (subsequent calls are ignored), which keeps test setup simple.
pub fn set_random_source(source: &'static dyn RandomSource) {
    RNG.call_once(|| source);
}

/// Fill `buf` with random bytes from the installed source.
///
/// Returns `CryptoFailed` if no source has been installed — encoding metadata
/// without a randomness source is a programming error (the integrator must call
/// [`set_random_source`] at startup).
pub fn fill_random(buf: &mut [u8]) -> VckResult<()> {
    match RNG.get() {
        Some(src) => src.fill(buf),
        None => Err(VckError::CryptoFailed("no RandomSource installed")),
    }
}
