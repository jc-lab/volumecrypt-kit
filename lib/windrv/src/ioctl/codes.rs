//! IOCTL codes. MUST stay in sync with `sdk/ioctl.go`.
//!
//! Built from the shared `CTL_CODE` helper in `vck_common::ioctl` so the bit
//! layout lives in exactly one place. The `const` assertions below pin each
//! value to the exact hex the Go SDK copies; they are checked at compile time on
//! every driver build, and the same hex is independently verified by the host
//! unit tests in `lib/common/src/ioctl.rs`.
//!
//! Access policy: read-only queries (status / progress) require
//! `FILE_READ_ACCESS`; everything that mutates driver or volume state requires
//! `FILE_WRITE_ACCESS`.

use vck_common::ioctl::{
    ctl_code, FILE_DEVICE_VCK, FILE_READ_ACCESS, FILE_WRITE_ACCESS, METHOD_BUFFERED,
};

/// Query encryption status (read-only). Function = 0x800.
pub const IOCTL_VCK_GET_STATUS: u32 =
    ctl_code(FILE_DEVICE_VCK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
/// Start incremental encryption. Function = 0x801.
pub const IOCTL_VCK_START_ENCRYPT: u32 =
    ctl_code(FILE_DEVICE_VCK, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS);
/// Start incremental decryption. Function = 0x802.
pub const IOCTL_VCK_START_DECRYPT: u32 =
    ctl_code(FILE_DEVICE_VCK, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS);
/// Query encryption progress (read-only). Function = 0x803.
pub const IOCTL_VCK_GET_PROGRESS: u32 =
    ctl_code(FILE_DEVICE_VCK, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS);
/// Pause an in-progress sweep. Function = 0x804.
pub const IOCTL_VCK_PAUSE: u32 =
    ctl_code(FILE_DEVICE_VCK, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS);
/// Phase-2 attach: read metadata + activate the encryption layer. Function = 0x805.
pub const IOCTL_JVCK_ATTACH: u32 =
    ctl_code(FILE_DEVICE_VCK, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS);
/// Detach a data volume (format-agnostic). Function = 0x806.
pub const IOCTL_VCK_DETACH: u32 =
    ctl_code(FILE_DEVICE_VCK, 0x806, METHOD_BUFFERED, FILE_WRITE_ACCESS);
/// Phase-1 attach: attach filter + activate size hiding so NTFS does not write
/// its VBR backup into the metadata region. The app then writes JVCK metadata
/// safely before calling IOCTL_JVCK_ATTACH (phase 2). Function = 0x807.
pub const IOCTL_JVCK_PREPARE: u32 =
    ctl_code(FILE_DEVICE_VCK, 0x807, METHOD_BUFFERED, FILE_WRITE_ACCESS);
/// Pause the OS (handover) volume's background sweep. Returns only after any
/// in-flight sweep batch has finished (driver-internal; sent on shutdown).
/// Function = 0x808.
pub const IOCTL_VCK_PAUSE_OS_VOLUME: u32 =
    ctl_code(FILE_DEVICE_VCK, 0x808, METHOD_BUFFERED, FILE_WRITE_ACCESS);
/// Detach every data (IOCTL-attached) volume; OS volumes are left bound.
/// Driver-internal; sent on shutdown/unload. Function = 0x809.
pub const IOCTL_VCK_DETACH_ALL_VOLUMES: u32 =
    ctl_code(FILE_DEVICE_VCK, 0x809, METHOD_BUFFERED, FILE_WRITE_ACCESS);

// Compile-time hex pinning. Any drift (wrong function/access) fails the build.
// These values are mirrored verbatim in `sdk/ioctl.go`.
const _: () = assert!(IOCTL_VCK_GET_STATUS == 0x0022_6000);
const _: () = assert!(IOCTL_VCK_START_ENCRYPT == 0x0022_a004);
const _: () = assert!(IOCTL_VCK_START_DECRYPT == 0x0022_a008);
const _: () = assert!(IOCTL_VCK_GET_PROGRESS == 0x0022_600c);
const _: () = assert!(IOCTL_VCK_PAUSE == 0x0022_a010);
const _: () = assert!(IOCTL_JVCK_ATTACH == 0x0022_a014);
const _: () = assert!(IOCTL_VCK_DETACH == 0x0022_a018);
const _: () = assert!(IOCTL_JVCK_PREPARE == 0x0022_a01c);
const _: () = assert!(IOCTL_VCK_PAUSE_OS_VOLUME == 0x0022_a020);
const _: () = assert!(IOCTL_VCK_DETACH_ALL_VOLUMES == 0x0022_a024);
