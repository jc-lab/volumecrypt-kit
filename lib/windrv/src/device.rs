// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Control device object + user-space symbolic link.
//!
//! Creates `\Device\VolumeCryptKitSample` and `\DosDevices\VolumeCryptKitSample`
//! so the Go SDK can `CreateFile(\\.\VolumeCryptKitSample)`.

use core::mem::size_of;
use core::ptr::null_mut;

use vck_common::VckResult;
use wdk_sys::{
    ntddk::{
        IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
        IoRegisterShutdownNotification, IoUnregisterShutdownNotification,
    },
    BOOLEAN, DO_BUFFERED_IO, DO_DEVICE_INITIALIZING, DRIVER_OBJECT, FILE_DEVICE_SECURE_OPEN,
    FILE_DEVICE_UNKNOWN, GUID, NTSTATUS, PCUNICODE_STRING, PDEVICE_OBJECT, UNICODE_STRING, ULONG,
};

use crate::nt::{ntstatus_to_result, UnicodeString};
use crate::registry::AttachedVolume;

// `IoCreateDeviceSecure` is declared in wdmsec.h, which wdk-sys does not bind.
// Declare the prototype and link wdmsec.lib (see this crate's build.rs). Unlike
// `IoCreateDevice`, it stamps the new device object with a caller-supplied SDDL
// security descriptor, so the OS enforces who may open the device (and with
// what access) at CreateFile time. The concrete SDDL is supplied by the driver
// binary via [`ControlDeviceSecurity`].
extern "C" {
    // In the WDK, `IoCreateDeviceSecure` is a macro aliasing the wdmsec.lib
    // export `WdmlibIoCreateDeviceSecure`; link against the real symbol.
    #[link_name = "WdmlibIoCreateDeviceSecure"]
    fn IoCreateDeviceSecure(
        driver_object: *mut DRIVER_OBJECT,
        device_extension_size: ULONG,
        device_name: *mut UNICODE_STRING,
        device_type: ULONG,
        device_characteristics: ULONG,
        exclusive: BOOLEAN,
        default_sddl_string: PCUNICODE_STRING,
        device_class_guid: *const GUID,
        device_object: *mut PDEVICE_OBJECT,
    ) -> NTSTATUS;
}

pub const DEVICE_NAME: &str = r"\Device\VolumeCryptKitSample";
pub const SYMLINK_NAME: &str = r"\DosDevices\VolumeCryptKitSample";

/// Security configuration for the control device, supplied by the driver binary
/// (the sample) rather than hardcoded in the framework. The `sddl` string is the
/// device DACL; pairing an admin-only-write SDDL with the per-IOCTL
/// `FILE_WRITE_ACCESS` bits (see `ioctl::codes`) restricts every state-mutating
/// IOCTL to administrators while still allowing read-only queries.
pub struct ControlDeviceSecurity<'a> {
    /// SDDL describing the device's DACL, e.g.
    /// `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;AU)`.
    pub sddl: &'a str,
    /// Custom device class GUID required by `IoCreateDeviceSecure` (private to
    /// the driver; identifies the device's security/setup class).
    pub class_guid: GUID,
}

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
    ///
    /// `security` (supplied by the driver binary) controls the device's SDDL so
    /// the OS gates who may open it and with what access. Non-exclusive so the
    /// management app and the driver's own shutdown self-IOCTL can both reach it.
    pub fn create(
        driver_object: *mut DRIVER_OBJECT,
        security: &ControlDeviceSecurity<'_>,
    ) -> VckResult<Self> {
        let device_name = UnicodeString::from_str(DEVICE_NAME);
        let symlink_name = UnicodeString::from_str(SYMLINK_NAME);
        let sddl = UnicodeString::from_str(security.sddl);
        let mut device_object = null_mut();

        ntstatus_to_result(unsafe {
            IoCreateDeviceSecure(
                driver_object,
                DEVICE_EXTENSION_SIZE,
                device_name.as_ptr(),
                FILE_DEVICE_UNKNOWN,
                FILE_DEVICE_SECURE_OPEN,
                BOOLEAN::default(),
                sddl.as_ptr() as PCUNICODE_STRING,
                &security.class_guid as *const GUID,
                &mut device_object,
            )
        }, "IoCreateDeviceSecure failed")?;

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

