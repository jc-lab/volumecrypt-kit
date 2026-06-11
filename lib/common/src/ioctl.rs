// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Windows device I/O control (IOCTL) code construction.
//!
//! Single source of truth for the `CTL_CODE` arithmetic shared across the kernel
//! driver and host tooling. The driver's concrete codes live in
//! `lib/windrv/src/ioctl/codes.rs` (built via [`ctl_code`] and pinned with
//! compile-time assertions); the Go SDK (`sdk/ioctl.go`) hardcodes the same hex
//! values, which are verified here by the host unit tests.
//!
//! A control code is laid out exactly like the Win32 `CTL_CODE` macro (`wdm.h`):
//!
//! ```text
//!  31              16 15 14 13             2 1    0
//! +------------------+-----+-----------------+------+
//! |    DeviceType    |Acces|     Function    |Method|
//! +------------------+-----+-----------------+------+
//! ```

/// `METHOD_BUFFERED` transfer type: I/O manager copies the in/out buffers.
pub const METHOD_BUFFERED: u32 = 0;
/// `METHOD_IN_DIRECT` transfer type.
pub const METHOD_IN_DIRECT: u32 = 1;
/// `METHOD_OUT_DIRECT` transfer type.
pub const METHOD_OUT_DIRECT: u32 = 2;
/// `METHOD_NEITHER` transfer type.
pub const METHOD_NEITHER: u32 = 3;

/// `FILE_ANY_ACCESS`: no specific access is required to issue the IOCTL.
pub const FILE_ANY_ACCESS: u32 = 0;
/// `FILE_READ_ACCESS`: the caller's handle must grant read access. Use for
/// read-only query IOCTLs (status / progress).
pub const FILE_READ_ACCESS: u32 = 0x0001;
/// `FILE_WRITE_ACCESS`: the caller's handle must grant write access. Use for
/// IOCTLs that mutate driver or volume state (attach / detach / encrypt / pause).
pub const FILE_WRITE_ACCESS: u32 = 0x0002;

/// Device type for all VolumeCryptKit control codes. `0x22` is
/// `FILE_DEVICE_UNKNOWN`; values below `0x8000` are reserved for Microsoft but
/// are conventionally reused by sample drivers.
pub const FILE_DEVICE_VCK: u32 = 0x22;

/// Build a device control code, equivalent to the Win32 `CTL_CODE` macro:
///
/// ```text
/// ((device_type) << 16) | ((access) << 14) | ((function) << 2) | (method)
/// ```
///
/// `function` numbers below `0x800` are reserved by Microsoft; custom codes use
/// `0x800..=0xFFF`.
#[inline]
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// `macro_rules!` spelling of [`ctl_code`], mirroring the C `CTL_CODE` macro for
/// call sites that prefer macro syntax. Both forms expand to the same value; the
/// `const fn` is preferred in `const` definitions because it is type-checked.
#[macro_export]
macro_rules! ctl_code {
    ($device_type:expr, $function:expr, $method:expr, $access:expr) => {
        $crate::ioctl::ctl_code($device_type, $function, $method, $access)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bit layout must match `wdm.h` exactly. These golden hex values are the
    /// contract: `lib/windrv/src/ioctl/codes.rs` pins the same values with
    /// `const` assertions and `sdk/ioctl.go` copies them verbatim.
    #[test]
    fn ctl_code_matches_windows_layout() {
        // DeviceType occupies bits 31..16.
        assert_eq!(ctl_code(0x22, 0, METHOD_BUFFERED, FILE_ANY_ACCESS), 0x0022_0000);
        // Access occupies bits 15..14.
        assert_eq!(ctl_code(0, 0, METHOD_BUFFERED, FILE_READ_ACCESS), 0x0000_4000);
        assert_eq!(ctl_code(0, 0, METHOD_BUFFERED, FILE_WRITE_ACCESS), 0x0000_8000);
        // Function occupies bits 13..2.
        assert_eq!(ctl_code(0, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS), 0x0000_2000);
        // Method occupies bits 1..0.
        assert_eq!(ctl_code(0, 0, METHOD_NEITHER, FILE_ANY_ACCESS), 0x0000_0003);
    }

    /// Golden table of every VolumeCryptKit IOCTL value. Keep in lockstep with
    /// `lib/windrv/src/ioctl/codes.rs` and `sdk/ioctl.go`.
    #[test]
    fn vck_ioctl_codes_are_exact() {
        let dt = FILE_DEVICE_VCK;
        let m = METHOD_BUFFERED;
        let r = FILE_READ_ACCESS;
        let w = FILE_WRITE_ACCESS;

        // Read-only queries → FILE_READ_ACCESS.
        assert_eq!(ctl_code(dt, 0x800, m, r), 0x0022_6000); // GET_STATUS
        assert_eq!(ctl_code(dt, 0x803, m, r), 0x0022_600c); // GET_PROGRESS

        // State-mutating commands → FILE_WRITE_ACCESS.
        assert_eq!(ctl_code(dt, 0x801, m, w), 0x0022_a004); // START_ENCRYPT
        assert_eq!(ctl_code(dt, 0x802, m, w), 0x0022_a008); // START_DECRYPT
        assert_eq!(ctl_code(dt, 0x804, m, w), 0x0022_a010); // PAUSE
        assert_eq!(ctl_code(dt, 0x805, m, w), 0x0022_a014); // JVCK_ATTACH
        assert_eq!(ctl_code(dt, 0x806, m, w), 0x0022_a018); // VCK_DETACH
        assert_eq!(ctl_code(dt, 0x807, m, w), 0x0022_a01c); // JVCK_PREPARE
        assert_eq!(ctl_code(dt, 0x808, m, w), 0x0022_a020); // PAUSE_OS_VOLUME
        assert_eq!(ctl_code(dt, 0x809, m, w), 0x0022_a024); // DETACH_ALL_VOLUMES

        // Benchmark (FILE_READ_ACCESS — no state mutation).
        assert_eq!(ctl_code(dt, 0x80a, m, r), 0x0022_6028); // BENCH_AES
    }

    #[test]
    fn macro_and_fn_agree() {
        assert_eq!(
            ctl_code!(FILE_DEVICE_VCK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS),
            ctl_code(FILE_DEVICE_VCK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS),
        );
    }
}
