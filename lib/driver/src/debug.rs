extern crate alloc;

use alloc::ffi::CString;
use alloc::string::String;
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use wdk_sys::ntddk::DbgPrint;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const DEBUGCON_PORT: u16 = 0x00e9;

pub fn debug_print(args: fmt::Arguments<'_>) {
    let mut line = String::new();
    if line.write_fmt(args).is_err() {
        return;
    }

    if !line.ends_with('\n') {
        line.push('\n');
    }

    let message = match CString::new(line) {
        Ok(message) => message,
        Err(_) => return,
    };

    unsafe {
        DbgPrint(c"%s".as_ptr().cast(), message.as_ptr());
    }

    if cfg!(feature = "debugcon") {
        write_debugcon(message.as_bytes_with_nul());
    }
}

pub fn panic_print(info: &PanicInfo<'_>) -> ! {
    let mut writer = PanicWriter::new();
    let _ = writer.write_str("panic: ");
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
    if let Some(message) = info.payload().downcast_ref::<&str>() {
        let _ = writer.write_str(message);
    } else if let Some(message) = info.payload().downcast_ref::<alloc::string::String>() {
        let _ = writer.write_str(message.as_str());
    } else {
        let _ = writer.write_str("<unknown panic payload>");
    }
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

#[macro_export]
macro_rules! driver_print {
    ($($arg:tt)*) => {
        $crate::debug::debug_print(core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! driver_println {
    () => {
        $crate::debug::debug_print(core::format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::debug::debug_print(core::format_args!($($arg)*))
    };
}
