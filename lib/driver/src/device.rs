//! Control device object + user-space symbolic link.
//!
//! Creates `\Device\VolumeCryptKitSample` and `\DosDevices\VolumeCryptKitSample`
//! so the Go SDK can `CreateFile(\\.\VolumeCryptKitSample)`.

use core::mem::size_of;
use core::ptr::null_mut;

use vck_common::VckResult;
use wdk_sys::{
    ntddk::{
        IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
        IoRegisterShutdownNotification, IoUnregisterShutdownNotification,
    },
    BOOLEAN, DO_BUFFERED_IO, DO_DEVICE_INITIALIZING, DRIVER_OBJECT, FILE_DEVICE_SECURE_OPEN,
    FILE_DEVICE_UNKNOWN, PDEVICE_OBJECT,
};

use crate::nt::{ntstatus_to_result, UnicodeString};
use crate::registry::AttachedVolume;

pub const DEVICE_NAME: &str = r"\Device\VolumeCryptKitSample";
pub const SYMLINK_NAME: &str = r"\DosDevices\VolumeCryptKitSample";

/// Discriminates which kind of device object an IRP arrived on, since the
/// control device and every filter device share this driver's MajorFunction
/// table.
pub const DEVICE_KIND_CONTROL: u32 = 0;
pub const DEVICE_KIND_FILTER: u32 = 1;

/// Stored in every device object's `DeviceExtension`.
#[repr(C)]
pub struct DeviceExtension {
    pub kind: u32,
    /// Filter only: the device immediately below us in the stack.
    pub lower_device: PDEVICE_OBJECT,
    /// Filter only: raw `Arc<AttachedVolume>` (via `Arc::into_raw`), released on
    /// detach.
    pub volume: *const AttachedVolume,
    /// Filter only: owned per-volume IO+sweep thread (raw `Box` pointer), created
    /// at bind, stopped and freed at detach. Null until a cipher-ready volume is
    /// bound. See [`crate::filter::volume_thread::VolumeThread`].
    pub vthread: *mut crate::filter::volume_thread::VolumeThread,
}

impl DeviceExtension {
    /// Borrow the extension of `device`.
    ///
    /// # Safety
    /// `device` must be one of this driver's device objects (created with a
    /// `DeviceExtension`-sized extension).
    pub unsafe fn of<'a>(device: PDEVICE_OBJECT) -> &'a DeviceExtension {
        &*((*device).DeviceExtension as *const DeviceExtension)
    }
}

pub(crate) const DEVICE_EXTENSION_SIZE: u32 = size_of::<DeviceExtension>() as u32;

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
                DEVICE_EXTENSION_SIZE,
                device_name.as_ptr(),
                FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_SECURE_OPEN,
                BOOLEAN::default(),
                &mut device_object,
            )
        }, "IoCreateDevice failed")?;

        unsafe {
            (*device_object).Flags |= DO_BUFFERED_IO;
            let ext = (*device_object).DeviceExtension as *mut DeviceExtension;
            (*ext).kind = DEVICE_KIND_CONTROL;
            (*ext).lower_device = null_mut();
            (*ext).volume = null_mut();
            (*ext).vthread = null_mut();
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
            // Request IRP_MJ_SHUTDOWN at system shutdown so the driver can pause
            // the encryption sweep cleanly before I/O is cut off (best-effort).
            let _ = IoRegisterShutdownNotification(device_object);
        }

        Ok(Self { device_object })
    }

    /// The control device object (target for self-sent IOCTLs from
    /// shutdown/unload).
    pub fn device_object(&self) -> PDEVICE_OBJECT {
        self.device_object
    }

    /// Delete the symbolic link and device object.
    pub fn destroy(self) -> VckResult<()> {
        let symlink_name = UnicodeString::from_str(SYMLINK_NAME);
        unsafe {
            IoUnregisterShutdownNotification(self.device_object);
        }
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

