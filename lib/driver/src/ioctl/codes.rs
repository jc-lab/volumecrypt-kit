//! IOCTL codes. MUST stay in sync with `sdk/ioctl.go`.
//!
//! `CTL_CODE(DeviceType=0x22, Function, METHOD_BUFFERED, FILE_ANY_ACCESS)`
//! = `(0x22 << 16) | (Function << 2)`.

pub const IOCTL_VCK_GET_STATUS: u32 = 0x0022_2000; // Function = 0x800 (common)
pub const IOCTL_VCK_START_ENCRYPT: u32 = 0x0022_2004; // Function = 0x801 (common)
pub const IOCTL_VCK_START_DECRYPT: u32 = 0x0022_2008; // Function = 0x802 (common)
pub const IOCTL_VCK_GET_PROGRESS: u32 = 0x0022_200c; // Function = 0x803 (common)
pub const IOCTL_VCK_PAUSE: u32 = 0x0022_2010; // Function = 0x804 (common)
/// Phase-1 attach: attach filter + activate size hiding so NTFS does not write
/// its VBR backup into the metadata region. The app then writes JVCK metadata
/// safely before calling IOCTL_JVCK_ATTACH (phase 2).
pub const IOCTL_JVCK_PREPARE: u32 = 0x0022_201c; // Function = 0x807
pub const IOCTL_JVCK_ATTACH: u32 = 0x0022_2014; // Function = 0x805 (phase 2: read metadata)
pub const IOCTL_VCK_DETACH: u32 = 0x0022_2018; // Function = 0x806 (common, format-agnostic)
