//! Control device object + user-space symbolic link.
//!
//! Creates `\Device\VolumeCryptKitSample` and `\DosDevices\VolumeCryptKitSample`
//! so the Go SDK can `CreateFile(\\.\VolumeCryptKitSample)`.

use alloc::vec::Vec;
use core::ptr::null_mut;

use vck_common::VckResult;
use wdk_sys::{
    ntddk::{IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink, RtlInitUnicodeString},
    BOOLEAN, DO_BUFFERED_IO, DO_DEVICE_INITIALIZING, DRIVER_OBJECT, FILE_DEVICE_SECURE_OPEN,
    FILE_DEVICE_UNKNOWN, NTSTATUS, PDEVICE_OBJECT, UNICODE_STRING,
};

pub const DEVICE_NAME: &str = r"\Device\VolumeCryptKitSample";
pub const SYMLINK_NAME: &str = r"\DosDevices\VolumeCryptKitSample";

pub struct ControlDevice {
    device_object: PDEVICE_OBJECT,
}

unsafe impl Send for ControlDevice {}
unsafe impl Sync for ControlDevice {}

impl ControlDevice {
    /// Create the control device object and its symbolic link.
    pub fn create(driver_object: *mut DRIVER_OBJECT) -> VckResult<Self> {
        let device_name = UnicodeString::from_str(DEVICE_NAME);
        let symlink_name = UnicodeString::from_str(SYMLINK_NAME);
        let mut device_object = null_mut();

        ntstatus_to_result(unsafe {
            IoCreateDevice(
                driver_object,
                0,
                device_name.as_ptr(),
                FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_SECURE_OPEN,
                BOOLEAN::default(),
                &mut device_object,
            )
        }, "IoCreateDevice failed")?;

        unsafe {
            (*device_object).Flags |= DO_BUFFERED_IO;
        }

        if let Err(err) = ntstatus_to_result(
            unsafe { IoCreateSymbolicLink(symlink_name.as_ptr(), device_name.as_ptr()) },
            "IoCreateSymbolicLink failed",
        ) {
            unsafe {
                IoDeleteDevice(device_object);
            }
            return Err(err);
        }

        unsafe {
            (*device_object).Flags &= !DO_DEVICE_INITIALIZING;
        }

        Ok(Self { device_object })
    }

    /// Delete the symbolic link and device object.
    pub fn destroy(self) -> VckResult<()> {
        let symlink_name = UnicodeString::from_str(SYMLINK_NAME);
        ntstatus_to_result(
            unsafe { IoDeleteSymbolicLink(symlink_name.as_ptr()) },
            "IoDeleteSymbolicLink failed",
        )?;
        unsafe {
            IoDeleteDevice(self.device_object);
        }
        Ok(())
    }
}

struct UnicodeString {
    value: UNICODE_STRING,
    buffer: Vec<u16>,
}

impl UnicodeString {
    fn from_str(value: &str) -> Self {
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
            buffer,
        }
    }

    fn as_ptr(&self) -> *mut UNICODE_STRING {
        let _ = &self.buffer;
        &self.value as *const UNICODE_STRING as *mut UNICODE_STRING
    }
}

fn ntstatus_to_result(status: NTSTATUS, context: &'static str) -> VckResult<()> {
    if status >= 0 {
        Ok(())
    } else {
        Err(vck_common::VckError::Io(context.into()))
    }
}
