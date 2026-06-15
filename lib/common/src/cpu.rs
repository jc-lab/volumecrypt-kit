// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! CPU feature detection shared by the kernel driver and the UEFI loader.

/// Returns true if the CPU advertises AES-NI (CPUID.01H:ECX.AESNI[bit 25]).
///
/// This is the same hardware bit the `aes` crate's runtime detection uses to
/// select its AES-NI backend; we query it independently only to log support
/// status at startup.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn has_aes_ni() -> bool {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::__cpuid;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::__cpuid;

    // CPUID leaf 1, ECX bit 25 = AES-NI.
    const ECX_AESNI: u32 = 1 << 25;
    // SAFETY: leaf 1 is supported on every x86 CPU that runs 64-bit Windows/UEFI.
    // `#[allow(unused_unsafe)]`: `__cpuid` is `unsafe` on some toolchains and
    // safe on others; keep the block for the former without warning on the latter.
    #[allow(unused_unsafe)]
    let info = unsafe { __cpuid(1) };
    info.ecx & ECX_AESNI != 0
}

/// Non-x86 fallback: no AES-NI.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn has_aes_ni() -> bool {
    false
}
