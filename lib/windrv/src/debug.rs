// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

use alloc::ffi::CString;
use alloc::string::String;
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use log::{Metadata, Record};
use wdk_sys::ntddk::DbgPrint;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const DEBUGCON_PORT: u16 = 0x00e9;

// 100-ns intervals between the Windows epoch (1601-01-01) and the Unix epoch (1970-01-01).
const FILETIME_EPOCH_DIFF: u64 = 116_444_736_000_000_000;

/// Returns `(unix_seconds, milliseconds)` from the system clock.
fn get_timestamp() -> (u64, u32) {
    use crate::ntddk_ex::KeQuerySystemTime;
    let unix_100ns = KeQuerySystemTime().saturating_sub(FILETIME_EPOCH_DIFF);
    let secs = unix_100ns / 10_000_000;
    let millis = ((unix_100ns % 10_000_000) / 10_000) as u32;
    (secs, millis)
}

// `IoGetRemainingStackSize` is a header inline (not an ntoskrnl export), so we
// compute the same thing from the current RSP and the thread's stack limit.
// `PsGetCurrentThreadStackLimit` IS a real export; declare it like the rest of
// the kernel routines (resolved against ntoskrnl.lib at link time).
extern "system" {
    fn PsGetCurrentThreadStackLimit() -> usize;
}

/// Approximate remaining kernel stack in bytes (current RSP minus the thread
/// stack limit). Useful for spotting stack-pressure on the metadata/crypto path.
pub fn remaining_stack() -> u64 {
    let rsp: usize;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    let limit = unsafe { PsGetCurrentThreadStackLimit() };
    rsp.saturating_sub(limit) as u64
}

pub fn panic_print(info: &PanicInfo<'_>) -> ! {
    let mut writer = PanicWriter::new();
    let (secs, millis) = get_timestamp();
    let _ = write!(&mut writer, "{secs}.{millis:03} vck-windrv: panic: ");
    if let Some(location) = info.location() {
        let _ = write!(
            &mut writer,
            "{}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    } else {
        let _ = writer.write_str("<unknown location>");
    }
    let _ = writer.write_str(" ");
    let _ = write!(&mut writer, "{}", info.message());
    if !writer.ends_with_newline() {
        let _ = writer.write_char('\n');
    }
    writer.flush();
    loop {
        core::hint::spin_loop();
    }
}

struct PanicWriter {
    buf: [u8; 512],
    len: usize,
}

impl PanicWriter {
    fn new() -> Self {
        Self {
            buf: [0; 512],
            len: 0,
        }
    }

    fn ends_with_newline(&self) -> bool {
        self.len > 0 && self.buf[self.len - 1] == b'\n'
    }

    fn flush(&self) {
        let mut line = [0u8; 513];
        let len = self.len.min(512);
        line[..len].copy_from_slice(&self.buf[..len]);
        line[len] = 0;

        unsafe {
            DbgPrint(c"%s".as_ptr().cast(), line.as_ptr());
        }

        if cfg!(feature = "debugcon") {
            write_debugcon(&line[..=len]);
        }
    }
}

impl Write for PanicWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let available = self.buf.len().saturating_sub(self.len);
        if available == 0 {
            return Err(fmt::Error);
        }
        let to_copy = core::cmp::min(available, s.len());
        self.buf[self.len..self.len + to_copy].copy_from_slice(&s.as_bytes()[..to_copy]);
        self.len += to_copy;
        if to_copy < s.len() {
            return Err(fmt::Error);
        }
        Ok(())
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn write_debugcon(bytes: &[u8]) {
    for &byte in bytes {
        if byte == 0 {
            break;
        }
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") DEBUGCON_PORT,
                in("al") byte,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn write_debugcon(_bytes: &[u8]) {}

struct WinDrvLogger;

impl log::Log for WinDrvLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let (secs, millis) = get_timestamp();
        let mut line = String::new();
        let _ = writeln!(
            &mut line,
            "{}.{:03} vck-windrv: [{}] {}",
            secs,
            millis,
            record.level(),
            record.args()
        );

        let message = match CString::new(line) {
            Ok(msg) => msg,
            Err(_) => return,
        };

        unsafe {
            DbgPrint(c"%s".as_ptr().cast(), message.as_ptr());
        }

        #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "debugcon"))]
        write_debugcon(message.as_bytes_with_nul());
    }

    fn flush(&self) {}
}

/// Initialize the logger for the driver.
/// Outputs to DbgPrint and, on x86/x86_64 architectures, also to the QEMU
/// ISA debug console (port 0xE9) when available.
pub fn init_logger() {
    let _ = log::set_logger(&WinDrvLogger).map(|()| log::set_max_level(log::LevelFilter::Trace));
}
