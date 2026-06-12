// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal loader debug output to the QEMU ISA debug console (port 0xE9).
//!
//! The driver writes its diagnostics to port 0xE9 (`lib/windrv/src/debug.rs`),
//! and the test recipes capture that port to `debug.log`. UEFI applications run
//! at ring 0, so the loader can write to the same port directly — this gives the
//! loader a diagnostic channel that survives into the captured `debug.log`
//! (unlike the UEFI logger, which only reaches the transient console/serial).

use core::fmt::{self, Write};

/// QEMU `isa-debugcon` I/O port.
const DEBUGCON_PORT: u16 = 0xE9;

#[inline]
fn out_u8(byte: u8) {
    // SAFETY: writing a byte to the debug console port has no memory effect and
    // is harmless on real firmware (the port is typically unmapped / ignored).
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") DEBUGCON_PORT,
            in("al") byte,
            options(nomem, nostack, preserves_flags),
        );
    }
}

struct DebugConsole;

impl Write for DebugConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            out_u8(b);
        }
        Ok(())
    }
}

/// Convert a UEFI `Time` to `(unix_seconds, milliseconds)`.
///
/// Uses Hinnant's proleptic Gregorian algorithm (shift epoch to March 1 so
/// leap-day handling is uniform) — no allocation, no lookup tables.
fn efi_time_to_unix(t: &uefi::runtime::Time) -> (u64, u32) {
    let year = t.year() as u64;
    let month = t.month() as u64;
    let day = t.day() as u64;

    // Shift year boundary to March 1 so the leap day is always at year end.
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };

    // Days from the proleptic Gregorian epoch (0000-03-01) to 1970-01-01.
    const EPOCH_DAYS: u64 = 719_468;

    let era = y / 400;
    let yoe = y % 400; // year-of-era [0, 399]
    let doy = (153 * m + 2) / 5 + day - 1; // day-of-year [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // day-of-era [0, 146096]
    let days = era * 146_097 + doe - EPOCH_DAYS;

    let secs = days * 86_400
        + t.hour() as u64 * 3_600
        + t.minute() as u64 * 60
        + t.second() as u64;
    let millis = t.nanosecond() / 1_000_000;
    (secs, millis)
}

/// Returns `(unix_seconds, milliseconds)` from the UEFI runtime clock.
/// Falls back to `(0, 0)` if the clock is unavailable.
fn get_timestamp() -> (u64, u32) {
    match uefi::runtime::get_time() {
        Ok(t) => efi_time_to_unix(&t),
        Err(_) => (0, 0),
    }
}

/// Write a string to the debug console (port 0xE9).
pub fn write_str(s: &str) {
    let _ = DebugConsole.write_str(s);
}

/// `write!`-style formatted output to the debug console.
pub fn write_fmt(args: fmt::Arguments<'_>) {
    let _ = DebugConsole.write_fmt(args);
}

/// Print a timestamped log line to the debug console.
///
/// Output format: `{secs}.{millis:03} {prefix}{args}\r\n`
pub fn write_log_line(prefix: &str, args: fmt::Arguments<'_>) {
    let (secs, millis) = get_timestamp();
    let _ = DebugConsole.write_fmt(format_args!("{secs}.{millis:03} "));
    let _ = DebugConsole.write_str(prefix);
    let _ = DebugConsole.write_fmt(args);
    let _ = DebugConsole.write_str("\r\n");
}

/// Print a timestamped, `vck-loader:`-prefixed line to the 0xE9 debug console.
///
/// This is the loader-side counterpart of the driver's `vck_log!`
/// (`lib/windrv/src/debug.rs`): same macro name and calling convention, same
/// `{timestamp} vck-<component>: <message>` output shape.
#[macro_export]
macro_rules! vck_log {
    ($($arg:tt)*) => {
        $crate::debug::write_log_line("vck-loader: ", core::format_args!($($arg)*))
    };
}
