//! Volume filter device attach/detach.
//!
//! Creates an unnamed filter device object and attaches it above a target
//! volume's device stack via `IoAttachDeviceToDeviceStackSafe`, tagging the
//! device extension so the shared MajorFunction handlers can route IRPs.

use alloc::sync::Arc;
use core::ptr::null_mut;

use vck_common::{VckError, VckResult};
use wdk_sys::{
    ntddk::{
        IoAttachDeviceToDeviceStackSafe, IoCreateDevice, IoDeleteDevice, IoDetachDevice,
        IoGetDeviceObjectPointer, ObfDereferenceObject,
    },
    DEVICE_OBJECT, DO_BUFFERED_IO, DO_DEVICE_INITIALIZING, DO_DIRECT_IO, DO_POWER_PAGABLE,
    DRIVER_OBJECT, FILE_DEVICE_DISK, FILE_READ_DATA, PDEVICE_OBJECT, PFILE_OBJECT,
};

use crate::{
    device::{DeviceExtension, DEVICE_EXTENSION_SIZE, DEVICE_KIND_FILTER},
    nt::{nt_success, UnicodeString},
    registry::AttachedVolume,
};

/// Create a filter device and attach it above the volume named by
/// `target_nt_path` (e.g. `\??\D:`). On success the returned device object's
/// extension owns a reference to `volume` (released by [`detach_filter`]).
pub fn attach_filter(
    driver: *mut DRIVER_OBJECT,
    target_nt_path: &str,
    volume: Arc<AttachedVolume>,
) -> VckResult<PDEVICE_OBJECT> {
    let mut filter_do: PDEVICE_OBJECT = null_mut();
    let status = unsafe {
        IoCreateDevice(
            driver,
            DEVICE_EXTENSION_SIZE,
            null_mut(), // unnamed
            FILE_DEVICE_DISK,
            0,
            0, // Exclusive = FALSE
            &mut filter_do,
        )
    };
    if !nt_success(status) {
        return Err(VckError::Io("IoCreateDevice(filter) failed".into()));
    }

    // Resolve the target volume device (top of its stack right now).
    let name = UnicodeString::from_str(target_nt_path);
    let mut file_obj: PFILE_OBJECT = null_mut();
    let mut target_do: PDEVICE_OBJECT = null_mut();
    let status =
        unsafe { IoGetDeviceObjectPointer(name.as_ptr(), FILE_READ_DATA, &mut file_obj, &mut target_do) };
    if !nt_success(status) {
        unsafe { IoDeleteDevice(filter_do) };
        return Err(VckError::Io("IoGetDeviceObjectPointer(target) failed".into()));
    }

    // Attach above the target. The attach holds its own stack reference, so the
    // IoGetDeviceObjectPointer reference can be released immediately after.
    let mut lower: PDEVICE_OBJECT = null_mut();
    let status = unsafe { IoAttachDeviceToDeviceStackSafe(filter_do, target_do, &mut lower) };
    unsafe { ObfDereferenceObject(file_obj.cast()) };
    if !nt_success(status) || lower.is_null() {
        unsafe { IoDeleteDevice(filter_do) };
        return Err(VckError::Io("IoAttachDeviceToDeviceStackSafe failed".into()));
    }

    unsafe {
        let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
        (*ext).kind = DEVICE_KIND_FILTER;
        (*ext).lower_device = lower;
        (*ext).volume = Arc::into_raw(volume);

        // Inherit the relevant flags / type from the device below us.
        (*filter_do).Flags |= (*lower).Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
        (*filter_do).DeviceType = (*lower).DeviceType;
        (*filter_do).Characteristics = (*lower).Characteristics;
        (*filter_do).Flags &= !DO_DEVICE_INITIALIZING;
    }

    Ok(filter_do)
}

/// Detach and delete a filter device, releasing the `Arc<AttachedVolume>` held
/// in its extension.
pub fn detach_filter(filter_do: PDEVICE_OBJECT) {
    if filter_do.is_null() {
        return;
    }
    unsafe {
        let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
        if !(*ext).lower_device.is_null() {
            IoDetachDevice((*ext).lower_device);
            (*ext).lower_device = null_mut();
        }
        if !(*ext).volume.is_null() {
            drop(Arc::from_raw((*ext).volume));
            (*ext).volume = null_mut();
        }
        IoDeleteDevice(filter_do);
    }
}

// Type alias kept for callers that referenced the old name.
pub type FilterDevice = *mut DEVICE_OBJECT;
