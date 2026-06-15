// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Small shared helpers around the raw WDK/NT bindings: `UNICODE_STRING`
//! construction, `NTSTATUS` checking, and common status constants.

use alloc::{format, string::String, vec::Vec};
use core::ptr::null_mut;

use vck_common::{VckError, VckResult};
use wdk_sys::{ntddk::RtlInitUnicodeString, NTSTATUS, UNICODE_STRING};

pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_PENDING: NTSTATUS = 0x0000_0103;
pub const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC000_0001u32 as i32;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000_000Du32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS = 0xC000_009Au32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC000_0023u32 as i32;

/// `true` for any non-error `NTSTATUS` (sign bit clear).
#[inline]
pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Map an `NTSTATUS` to a `VckResult`, attaching a static context string.
pub fn ntstatus_to_result(status: NTSTATUS, context: &'static str) -> VckResult<()> {
    if nt_success(status) {
        Ok(())
    } else {
        Err(VckError::Io(context.into()))
    }
}

/// Owns the UTF-16 buffer backing a `UNICODE_STRING`.
pub struct UnicodeString {
    value: UNICODE_STRING,
    // Keeps the NUL-terminated UTF-16 buffer alive for the lifetime of `value`.
    _buffer: Vec<u16>,
}

impl UnicodeString {
    pub fn new(value: &str) -> Self {
        let mut buffer: Vec<u16> = value.encode_utf16().collect();
        buffer.push(0);

        let mut unicode = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: null_mut(),
        };
        unsafe {
            RtlInitUnicodeString(&mut unicode, buffer.as_ptr());
        }

        Self {
            value: unicode,
            _buffer: buffer,
        }
    }

    pub fn as_ptr(&self) -> *mut UNICODE_STRING {
        &self.value as *const UNICODE_STRING as *mut UNICODE_STRING
    }
}

/// Convert a Win32 volume path to an NT object path usable with
/// `IoGetDeviceObjectPointer`.
///
/// Examples: `\\.\D:` -> `\??\D:`, `\\?\Volume{...}\` -> `\??\Volume{...}`,
/// `D:` -> `\??\D:`. Already-NT paths (`\Device\...`, `\??\...`) pass through.
pub fn win32_volume_path_to_nt(path: &str) -> String {
    let trimmed = path.trim_end_matches('\\');
    if let Some(rest) = trimmed.strip_prefix(r"\\.\") {
        format!(r"\??\{rest}")
    } else if let Some(rest) = trimmed.strip_prefix(r"\\?\") {
        format!(r"\??\{rest}")
    } else if trimmed.starts_with(r"\??\")
        || trimmed.starts_with(r"\Device\")
        || trimmed.starts_with(r"\DosDevices\")
    {
        String::from(trimmed)
    } else {
        format!(r"\??\{trimmed}")
    }
}
