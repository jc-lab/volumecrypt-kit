// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Loader-side CPU diagnostics and SSE/XMM enablement.
//!
//! The Block IO decrypt hook runs AES-256-XTS during the boot window, which on
//! AES-NI-capable CPUs executes SSE/AES-NI instructions (XMM registers). Those
//! require the OS-managed control-register bits to be set:
//!
//! - `CR0.MP[1] = 1`        — monitor coprocessor
//! - `CR0.EM[2] = 0`        — disable x87 emulation (else SSE faults with #UD)
//! - `CR4.OSFXSR[9] = 1`    — enable FXSAVE/FXRSTOR + SSE
//! - `CR4.OSXMMEXCPT[10] = 1` — route unmasked SSE FP exceptions to #XF
//!
//! UEFI firmware normally sets these already, but we verify and (when AES-NI is
//! present) set them defensively before any AES-NI code runs. The loader is a
//! ring-0 UEFI application, so writing CR0/CR4 is permitted.

use log::info;
use vck_common::cpu::has_aes_ni;

const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

#[inline]
fn read_cr0() -> u64 {
    let v: u64;
    // SAFETY: reading CR0 is a privileged but side-effect-free register read;
    // the loader runs at ring 0.
    unsafe {
        core::arch::asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn read_cr4() -> u64 {
    let v: u64;
    // SAFETY: as read_cr0, for CR4.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

#[inline]
fn write_cr0(v: u64) {
    // SAFETY: ring-0 control-register write. `nomem` is intentionally omitted:
    // toggling CR0 affects how the CPU executes, so the compiler must not move
    // memory accesses across it.
    unsafe {
        core::arch::asm!("mov cr0, {}", in(reg) v, options(nostack, preserves_flags));
    }
}

#[inline]
fn write_cr4(v: u64) {
    // SAFETY: as write_cr0, for CR4.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) v, options(nostack, preserves_flags));
    }
}

#[inline]
fn bit(v: u64, b: u64) -> u32 {
    ((v & b) != 0) as u32
}

/// Log AES-NI support and the SSE/XMM control bits, then (only when AES-NI is
/// supported) set them to the values required for AES-NI execution.
pub fn report_and_enable_xmm() {
    let aes = has_aes_ni();
    info!(
        "cpu: AES-NI {}",
        if aes { "supported" } else { "not supported" }
    );

    let cr0 = read_cr0();
    let cr4 = read_cr4();
    info!(
        "cpu: current CR0.MP[1]={} CR0.EM[2]={} CR4.OSFXSR[9]={} CR4.OSXMMEXCPT[10]={}",
        bit(cr0, CR0_MP),
        bit(cr0, CR0_EM),
        bit(cr4, CR4_OSFXSR),
        bit(cr4, CR4_OSXMMEXCPT),
    );

    if !aes {
        // No AES-NI: the aes crate uses its software backend; leave the control
        // registers as firmware configured them.
        return;
    }

    let new_cr0 = (cr0 | CR0_MP) & !CR0_EM;
    let new_cr4 = cr4 | CR4_OSFXSR | CR4_OSXMMEXCPT;
    if new_cr0 != cr0 {
        write_cr0(new_cr0);
    }
    if new_cr4 != cr4 {
        write_cr4(new_cr4);
    }
    info!(
        "cpu: enabled XMM CR0 {:#x}->{:#x} CR4 {:#x}->{:#x} (MP=1 EM=0 OSFXSR=1 OSXMMEXCPT=1)",
        cr0, new_cr0, cr4, new_cr4,
    );
}
