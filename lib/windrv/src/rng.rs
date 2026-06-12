// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Kernel cryptographic randomness source for `vck_common::rng`.
//!
//! The JVCK metadata store needs a fresh random salt every time it re-encodes
//! the EncryptedMetadata blob (each `encrypted_offset` persist). `lib/common` is
//! `no_std` and has no RNG, so the driver installs this one via
//! `vck_common::set_random_source(&KERNEL_RNG)` in `DriverEntry`.
//!
//! Backed by `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`, which is
//! callable at IRQL <= PASSIVE_LEVEL in kernel mode (metadata writes happen on
//! the per-volume PASSIVE_LEVEL thread). The import library is linked in
//! `build.rs` (`ksecdd`).

use core::ffi::c_void;

use vck_common::{rng::RandomSource, VckError, VckResult};
use wdk_sys::NTSTATUS;

// BCRYPT_USE_SYSTEM_PREFERRED_RNG: use the system-preferred RNG without opening
// an algorithm provider handle (pass a null algorithm handle).
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

extern "system" {
    fn BCryptGenRandom(
        h_algorithm: *mut c_void,
        pb_buffer: *mut u8,
        cb_buffer: u32,
        dw_flags: u32,
    ) -> NTSTATUS;
}

/// `RandomSource` backed by the kernel CNG system-preferred RNG.
pub struct KernelRng;

impl RandomSource for KernelRng {
    fn fill(&self, buf: &mut [u8]) -> VckResult<()> {
        // SAFETY: writes exactly `buf.len()` bytes into `buf`; null algorithm
        // handle is valid with BCRYPT_USE_SYSTEM_PREFERRED_RNG.
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(VckError::CryptoFailed("BCryptGenRandom failed"));
        }
        Ok(())
    }
}

/// Static instance to install with `vck_common::set_random_source`.
pub static KERNEL_RNG: KernelRng = KernelRng;
