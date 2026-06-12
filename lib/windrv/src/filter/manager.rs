// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Volume filter device attach/detach.
//!
//! Creates an unnamed filter device object and attaches it to a volume's
//! storage device stack. For NTFS I/O to pass through the filter (required for
//! transparent encryption), the filter must be placed BELOW the filesystem (NTFS)
//! and ABOVE the raw partition device — i.e.:
//!
//!   NTFS VCB
//!     └── [Our Filter]   ← must be here
//!          └── Raw Volume / Partition
//!
//! The only reliable way to achieve this without lock/dismount is via
//! `IoRegisterFsRegistrationChange` (see `register_fs_change` below): the
//! kernel calls our notification before the FSD finishes mounting, allowing us
//! to attach to the raw partition device BEFORE NTFS places its VCB above it.
//!
//! `attach_to_device` is the low-level primitive used by both the notification
//! path and the manual IOCTL path; the IOCTL path (`handle_jvck_attach`) calls
//! it before the FSD has had a chance to attach to the raw device by supplying
//! the raw partition device path directly.

use alloc::sync::Arc;
use core::ptr::null_mut;

use vck_common::{VckError, VckResult};
use wdk_sys::{
    ntddk::{
        IoAttachDeviceToDeviceStackSafe, IoCreateDevice, IoDeleteDevice, IoDetachDevice,
        IoGetDeviceObjectPointer, ObfDereferenceObject,
    },
    DEVICE_OBJECT, DO_BUFFERED_IO, DO_DEVICE_INITIALIZING, DO_DIRECT_IO, DO_POWER_PAGABLE,
    DRIVER_OBJECT, FILE_DEVICE_DISK, FILE_READ_DATA, FILE_WRITE_DATA, PDEVICE_OBJECT, PFILE_OBJECT,
};

use crate::{
    device::{DeviceExtension, DEVICE_EXTENSION_SIZE, DEVICE_KIND_FILTER},
    nt::{nt_success, UnicodeString},
    registry::AttachedVolume,
};

/// Create a filter device and attach it above the volume named by
/// `target_nt_path` (e.g. `\??\D:`). On success the returned device object's
/// extension owns a reference to `volume` (released by [`detach_filter`]).
/// Returns `(filter_device_object, lower_device_object)`.
///
/// The filter is attached to the CURRENT top of the device stack. If the FSD
/// (e.g. NTFS) has already mounted on the volume, the filter will land ABOVE
/// the FSD. For correct transparent encryption the caller should ensure the
/// filter is attached below the FSD (via the `IoRegisterFsRegistrationChange`
/// path) or accept size-interception-only semantics.
pub fn attach_filter(
    driver: *mut DRIVER_OBJECT,
    target_nt_path: &str,
    volume: Arc<AttachedVolume>,
) -> VckResult<(PDEVICE_OBJECT, PDEVICE_OBJECT)> {
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
    let status = unsafe {
        IoGetDeviceObjectPointer(
            name.as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA,
            &mut file_obj,
            &mut target_do,
        )
    };
    if !nt_success(status) {
        unsafe { IoDeleteDevice(filter_do) };
        return Err(VckError::Io("IoGetDeviceObjectPointer(target) failed".into()));
    }

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
        (*ext).volume = Arc::into_raw(volume.clone());
        (*ext).vthread = null_mut();
        crate::filter::volume_thread::bind(filter_do, volume);

        // Inherit the relevant flags / type from the device below us.
        (*filter_do).Flags |= (*lower).Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
        (*filter_do).DeviceType = (*lower).DeviceType;
        (*filter_do).Characteristics = (*lower).Characteristics;
        (*filter_do).Flags &= !DO_DEVICE_INITIALIZING;
    }

    crate::vck_log!(
        "filter: attached filter={:p} lower={:p} (NOTE: may be above FSD if FSD already mounted)",
        filter_do, lower
    );
    Ok((filter_do, lower))
}

/// Create and attach a filter device object without binding it to a volume yet.
///
/// Used when the volume metadata needs to be read AFTER the filter is in place
/// (e.g. the volume is dismounted so `ZwCreateFile` fails, but
/// `IoAttachDeviceToDeviceStackSafe` still works via `IoGetDeviceObjectPointer`).
/// Caller must call [`filter_bind_volume`] to complete setup once the
/// `AttachedVolume` is built. If setup fails, call [`detach_filter`] to clean up.
pub fn attach_filter_unbound(
    driver: *mut DRIVER_OBJECT,
    target_nt_path: &str,
) -> VckResult<(PDEVICE_OBJECT, PDEVICE_OBJECT)> {
    let mut filter_do: PDEVICE_OBJECT = null_mut();
    let status = unsafe {
        IoCreateDevice(
            driver,
            DEVICE_EXTENSION_SIZE,
            null_mut(),
            FILE_DEVICE_DISK,
            0,
            0,
            &mut filter_do,
        )
    };
    if !nt_success(status) {
        return Err(VckError::Io("IoCreateDevice(filter) failed".into()));
    }

    let name = UnicodeString::from_str(target_nt_path);
    let mut file_obj: PFILE_OBJECT = null_mut();
    let mut target_do: PDEVICE_OBJECT = null_mut();
    let status = unsafe {
        IoGetDeviceObjectPointer(
            name.as_ptr(),
            FILE_READ_DATA | FILE_WRITE_DATA,
            &mut file_obj,
            &mut target_do,
        )
    };
    if !nt_success(status) {
        unsafe { IoDeleteDevice(filter_do) };
        return Err(VckError::Io("IoGetDeviceObjectPointer(unbound) failed".into()));
    }

    let mut lower: PDEVICE_OBJECT = null_mut();
    let status = unsafe { IoAttachDeviceToDeviceStackSafe(filter_do, target_do, &mut lower) };
    unsafe { ObfDereferenceObject(file_obj.cast()) };
    if !nt_success(status) || lower.is_null() {
        unsafe { IoDeleteDevice(filter_do) };
        return Err(VckError::Io("IoAttachDeviceToDeviceStackSafe(unbound) failed".into()));
    }

    unsafe {
        // Mark as filter but leave volume pointer null until filter_bind_volume.
        let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
        (*ext).kind = DEVICE_KIND_FILTER;
        (*ext).lower_device = lower;
        (*ext).volume = null_mut();
        (*ext).vthread = null_mut();

        (*filter_do).Flags |= (*lower).Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
        (*filter_do).DeviceType = (*lower).DeviceType;
        (*filter_do).Characteristics = (*lower).Characteristics;
        (*filter_do).Flags &= !DO_DEVICE_INITIALIZING;
    }
    Ok((filter_do, lower))
}

/// Like [`attach_filter_unbound`] but takes a device object pointer directly
/// instead of resolving one via `IoGetDeviceObjectPointer`. Use this when the
/// device object is already known (e.g. obtained from an open file handle) and
/// `IoGetDeviceObjectPointer` would fail (e.g. after the filesystem dismounts).
pub fn attach_filter_to_raw_device(
    driver: *mut DRIVER_OBJECT,
    target_do: PDEVICE_OBJECT,
) -> VckResult<(PDEVICE_OBJECT, PDEVICE_OBJECT)> {
    let mut filter_do: PDEVICE_OBJECT = null_mut();
    let status = unsafe {
        IoCreateDevice(
            driver,
            DEVICE_EXTENSION_SIZE,
            null_mut(),
            FILE_DEVICE_DISK,
            0,
            0,
            &mut filter_do,
        )
    };
    if !nt_success(status) {
        return Err(VckError::Io("IoCreateDevice(filter-raw) failed".into()));
    }

    let mut lower: PDEVICE_OBJECT = null_mut();
    let status = unsafe { IoAttachDeviceToDeviceStackSafe(filter_do, target_do, &mut lower) };
    if !nt_success(status) || lower.is_null() {
        unsafe { IoDeleteDevice(filter_do) };
        return Err(VckError::Io("IoAttachDeviceToDeviceStackSafe(raw) failed".into()));
    }

    unsafe {
        let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
        (*ext).kind = DEVICE_KIND_FILTER;
        (*ext).lower_device = lower;
        (*ext).volume = null_mut(); // bound later via filter_bind_volume
        (*ext).vthread = null_mut();

        (*filter_do).Flags |= (*lower).Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
        (*filter_do).DeviceType = (*lower).DeviceType;
        (*filter_do).Characteristics = (*lower).Characteristics;
        (*filter_do).Flags &= !DO_DEVICE_INITIALIZING;
    }
    Ok((filter_do, lower))
}

/// Replace the `AttachedVolume` bound to an existing filter device. The old
/// volume Arc is properly dropped. Used by `handle_jvck_attach` to swap the
/// provisional (PREPARE-phase) volume for the complete (FVEK-ready) volume.
///
/// # Safety
/// `filter_do` must be a filter device object with a non-null `volume` pointer
/// set by a previous `filter_bind_volume` call.
pub unsafe fn filter_rebind_volume(filter_do: PDEVICE_OBJECT, volume: Arc<AttachedVolume>) {
    let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
    let old_ptr = (*ext).volume;
    if !old_ptr.is_null() {
        drop(Arc::from_raw(old_ptr));
    }
    (*ext).volume = Arc::into_raw(volume.clone());
    // Start the volume thread (if cipher now present) or swap its current volume.
    crate::filter::volume_thread::bind(filter_do, volume);
}

/// Bind an `AttachedVolume` to a previously unbound filter device (see
/// [`attach_filter_unbound`]).
///
/// # Safety
/// `filter_do` must be one returned by `attach_filter_unbound` that has not yet
/// been bound or detached.
pub unsafe fn filter_bind_volume(filter_do: PDEVICE_OBJECT, volume: Arc<AttachedVolume>) {
    let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
    (*ext).volume = Arc::into_raw(volume.clone());
    // Start the volume thread if this volume carries a cipher.
    crate::filter::volume_thread::bind(filter_do, volume);
}

/// Attach our filter to a specific device object (called from the
/// `IoRegisterFsRegistrationChange` notification path where we know the raw
/// partition device and can insert BELOW the FSD before it mounts).
pub fn attach_filter_to_device(
    driver: *mut DRIVER_OBJECT,
    target_do: PDEVICE_OBJECT,
    volume: Arc<AttachedVolume>,
) -> VckResult<(PDEVICE_OBJECT, PDEVICE_OBJECT)> {
    let mut filter_do: PDEVICE_OBJECT = null_mut();
    let status = unsafe {
        IoCreateDevice(
            driver,
            DEVICE_EXTENSION_SIZE,
            null_mut(),
            FILE_DEVICE_DISK,
            0,
            0,
            &mut filter_do,
        )
    };
    if !nt_success(status) {
        return Err(VckError::Io("IoCreateDevice(filter) failed".into()));
    }

    let mut lower: PDEVICE_OBJECT = null_mut();
    let status = unsafe { IoAttachDeviceToDeviceStackSafe(filter_do, target_do, &mut lower) };
    if !nt_success(status) || lower.is_null() {
        unsafe { IoDeleteDevice(filter_do) };
        return Err(VckError::Io("IoAttachDeviceToDeviceStackSafe(device) failed".into()));
    }

    unsafe {
        let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
        (*ext).kind = DEVICE_KIND_FILTER;
        (*ext).lower_device = lower;
        (*ext).volume = Arc::into_raw(volume.clone());
        (*ext).vthread = null_mut();
        crate::filter::volume_thread::bind(filter_do, volume);

        (*filter_do).Flags |= (*lower).Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
        (*filter_do).DeviceType = (*lower).DeviceType;
        (*filter_do).Characteristics = (*lower).Characteristics;
        (*filter_do).Flags &= !DO_DEVICE_INITIALIZING;
    }

    Ok((filter_do, lower))
}

/// Detach and delete a filter device, releasing the `Arc<AttachedVolume>` held
/// in its extension.
pub fn detach_filter(filter_do: PDEVICE_OBJECT) {
    if filter_do.is_null() {
        return;
    }
    unsafe {
        let ext = (*filter_do).DeviceExtension as *mut DeviceExtension;
        // Stop the per-volume IO+sweep thread FIRST so no thread touches the
        // lower device or the volume Arc after this point.
        if !(*ext).vthread.is_null() {
            let vt = alloc::boxed::Box::from_raw((*ext).vthread);
            vt.stop();
            (*ext).vthread = null_mut();
            // `vt` dropped here: drains any leftover IRPs + drops its volume Arc.
        }
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

/// Find our filter for the volume at `nt_path` using the PDO → filter map
/// built by add_device. Falls back to stack-walk for compatibility.
///
/// When AddDevice fires before NTFS mounts, the filter is at the correct
/// position. NTFS uses the VPB mechanism (not IoAttachDeviceToDeviceStackSafe)
/// for mounting, so stack-walking via IoGetLowerDeviceObject from the NTFS VCB
/// does NOT reach our filter. The PDO map approach is reliable.
/// Find the filter for the volume at `nt_path` using:
/// 1. Name-based PDO map lookup (primary — Volume class PDO ≠ namespace device object)
/// 2. Device pointer lookup in PDO map (fallback)
/// 3. Device stack walk (last resort)
pub fn find_filter_for_volume<F, FN>(
    nt_path: &str,
    lookup_fn: F,
    name_lookup_fn: FN,
) -> Option<(PDEVICE_OBJECT, PDEVICE_OBJECT)>
where
    F: Fn(PDEVICE_OBJECT) -> Option<(PDEVICE_OBJECT, PDEVICE_OBJECT)>,
    FN: Fn(&str) -> Option<(PDEVICE_OBJECT, PDEVICE_OBJECT)>,
{
    use wdk_sys::ntddk::{IoGetDeviceAttachmentBaseRef, ObfDereferenceObject};
    use wdk_sys::{FILE_READ_DATA, PFILE_OBJECT};

    let name = UnicodeString::from_str(nt_path);
    let mut file_obj: PFILE_OBJECT = null_mut();
    let mut vol_do: PDEVICE_OBJECT = null_mut();
    let status = unsafe {
        IoGetDeviceObjectPointer(name.as_ptr(), FILE_READ_DATA, &mut file_obj, &mut vol_do)
    };
    if !nt_success(status) || vol_do.is_null() {
        return None;
    }
    unsafe { ObfDereferenceObject(file_obj.cast()) };

    // Get the BASE device of the attachment stack for the volume. This is the
    // device object that was the PDO when AddDevice was called.
    let base_dev = unsafe { IoGetDeviceAttachmentBaseRef(vol_do) };
    crate::vck_log!(
        "find_filter: vol_do={:p} base_dev={:p} nt_path={}", vol_do, base_dev, nt_path
    );
    // Primary: name-based lookup using the actual device object name.
    // vol_do might be e.g. \Device\HarddiskVolume5 even if nt_path=\??\D:.
    // Query the name of vol_do directly.
    let dev_name = unsafe {
        use wdk_sys::ntddk::ObQueryNameString;
        let mut buf = [0u8; 256];
        let mut ret_len: u32 = 0;
        let st = ObQueryNameString(vol_do.cast(), buf.as_mut_ptr().cast(), 256, &mut ret_len);
        if st >= 0 {
            let name_len = u16::from_le_bytes([buf[0], buf[1]]) as usize / 2;
            let name_ptr = usize::from_le_bytes(buf[8..16].try_into().unwrap_or([0;8]));
            if name_len > 0 && name_ptr != 0 {
                let chars = core::slice::from_raw_parts(name_ptr as *const u16, name_len.min(64));
                let mut s = alloc::string::String::new();
                for &c in chars { if c >= 0x20 && c < 0x7F { s.push(c as u8 as char); } else { s.push('?'); } }
                s
            } else { alloc::string::String::new() }
        } else { alloc::string::String::new() }
    };
    crate::vck_log!("find_filter: vol_do_name='{}' nt_path='{}'", dev_name, nt_path);
    if !dev_name.is_empty() {
        if let Some(result) = name_lookup_fn(&dev_name) {
            crate::vck_log!("find_filter: found via vol_do_name={}", dev_name);
            return Some(result);
        }
    }
    // Also try nt_path directly.
    if let Some(result) = name_lookup_fn(nt_path) {
        crate::vck_log!("find_filter: found via nt_path={}", nt_path);
        return Some(result);
    }

    // Fallback: device pointer lookup
    if !base_dev.is_null() {
        unsafe { ObfDereferenceObject(base_dev.cast()) };
        if let Some(result) = lookup_fn(base_dev) {
            crate::vck_log!("find_filter: found via base_dev={:p}", base_dev);
            return Some(result);
        }
    }
    if let Some(result) = lookup_fn(vol_do) {
        crate::vck_log!("find_filter: found via vol_do={:p}", vol_do);
        return Some(result);
    }
    let top_dev = unsafe { wdk_sys::ntddk::IoGetAttachedDeviceReference(vol_do) };
    if !top_dev.is_null() {
        let result = lookup_fn(top_dev);
        unsafe { wdk_sys::ntddk::ObfDereferenceObject(top_dev.cast()) };
        if let Some(r) = result {
            crate::vck_log!("find_filter: found via top_dev={:p}", top_dev);
            return Some(r);
        }
    }

    // Final fallback: walk the attachment stack and match our filter device by
    // its extension kind. Handles path forms (e.g. `\??\Volume{GUID}`) whose
    // `IoGetDeviceObjectPointer` returns an unnamed upper device that no
    // name/pointer lookup matches, but which still sits in the same stack as our
    // AddDevice-attached filter — e.g. the OS volume queried by its volume GUID
    // instead of by its PDO name (`\Device\HarddiskVolumeN`).
    if let Some(result) = find_our_filter_in_stack(nt_path) {
        crate::vck_log!("find_filter: found via stack walk for {}", nt_path);
        return Some(result);
    }

    crate::vck_log!("find_filter: not found for {}", nt_path);
    None
}

/// Walk the device stack from the top of `nt_path` downward and return the
/// first filter device object that belongs to this driver, along with its
/// `lower_device`.
///
/// After `AddDevice` fires and NTFS mounts, the stack looks like:
///   NTFS VCB → [Our Filter] → Raw Partition/Volume
///
/// `IoGetDeviceObjectPointer(nt_path)` returns the NTFS VCB.
/// `IoGetLowerDeviceObject(NTFS_VCB)` returns Our Filter (since NTFS attached
/// above it). We verify by checking `DeviceExtension->kind == DEVICE_KIND_FILTER`.
///
/// Returns `Some((filter_do, lower_do))` if found, `None` otherwise.
pub fn find_our_filter_in_stack(nt_path: &str) -> Option<(PDEVICE_OBJECT, PDEVICE_OBJECT)> {
    use wdk_sys::ntddk::{IoGetLowerDeviceObject, ObfDereferenceObject};
    use wdk_sys::{FILE_READ_DATA, PFILE_OBJECT};

    use wdk_sys::ntddk::IoGetAttachedDeviceReference;

    let name = UnicodeString::from_str(nt_path);
    let mut file_obj: PFILE_OBJECT = null_mut();
    let mut vol_do: PDEVICE_OBJECT = null_mut();
    let status = unsafe {
        IoGetDeviceObjectPointer(name.as_ptr(), FILE_READ_DATA, &mut file_obj, &mut vol_do)
    };
    if !nt_success(status) || vol_do.is_null() {
        return None;
    }
    // Release the file object reference — we only need the device pointer.
    unsafe { ObfDereferenceObject(file_obj.cast()) };

    // IoGetDeviceObjectPointer returns the device the path NAME maps to (e.g.
    // HarddiskVolume5), which is NOT necessarily the stack top. Our filter
    // may be ABOVE it. Use IoGetAttachedDeviceReference to get the true top,
    // then walk downward to find our filter.
    let top_do = unsafe { IoGetAttachedDeviceReference(vol_do) };
    if top_do.is_null() {
        return None;
    }

    // Walk the attachment chain (top → bottom).
    unsafe {
        // top_do is already referenced by IoGetAttachedDeviceReference.
        let mut current = top_do;
        let mut depth = 0u32;
        loop {
            let ext = (*current).DeviceExtension as *const DeviceExtension;
            let kind = if !ext.is_null() { (*ext).kind } else { 0xFFFF_FFFF };
            crate::vck_log!(
                "find_filter[{}]: do={:p} ext_kind=0x{:08x}", depth, current, kind
            );
            if !ext.is_null() && (*ext).kind == DEVICE_KIND_FILTER {
                let lower = (*ext).lower_device;
                ObfDereferenceObject(current.cast());
                crate::vck_log!(
                    "find_filter: found filter_do={:p} lower={:p}", current, lower
                );
                return Some((current, lower));
            }
            // Move to the next device below.
            let next = IoGetLowerDeviceObject(current);
            ObfDereferenceObject(current.cast());
            if next.is_null() {
                crate::vck_log!("find_filter: reached base (depth={})", depth);
                break;
            }
            current = next;
            depth += 1;
            if depth > 12 { break; }
        }
    }
    None
}

// Type alias kept for callers that referenced the old name.
pub type FilterDevice = *mut DEVICE_OBJECT;
