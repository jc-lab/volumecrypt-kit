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

/// Write a string to the debug console (port 0xE9).
pub fn write_str(s: &str) {
    let _ = DebugConsole.write_str(s);
}

/// `write!`-style formatted output to the debug console.
pub fn write_fmt(args: fmt::Arguments<'_>) {
    let _ = DebugConsole.write_fmt(args);
}

/// Print a line (prefixed `vck-loader:`) to the debug console.
#[macro_export]
macro_rules! loader_dbg {
    ($($arg:tt)*) => {{
        $crate::debug::write_str("vck-loader: ");
        $crate::debug::write_fmt(core::format_args!($($arg)*));
        $crate::debug::write_str("\r\n");
    }};
}
