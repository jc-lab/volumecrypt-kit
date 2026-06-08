//! Chainloading the next EFI image.
//!
//! Loads and starts the next OS loader (e.g. the Windows Boot Manager,
//! `msbootmgfw.os.efi`) using `LoadImage` / `StartImage`. See ARCH.md boot flow
//! step 5.

use vck_common::VckResult;

use crate::provider::DevicePath;

/// Loads the EFI image at `next_loader` and transfers control to it.
///
/// On success this normally does not return (the next loader takes over);
/// if `StartImage` returns, the started image exited and control comes back.
///
/// Block IO hooks must remain installed across the chainload so the next loader
/// reads the OS volume transparently decrypted, but the loader's own resources
/// should otherwise be cleaned up before handing off.
pub fn chainload_next(next_loader: &DevicePath) -> VckResult<()> {
    // TODO(loader): in uefi 0.37 this maps to
    //   let image = uefi::boot::load_image(image_handle, LoadImageSource::FromDevicePath { device_path, .. })?;
    //   uefi::boot::start_image(image)?;
    // Convert VckError <- uefi::Error as the common crate does elsewhere.
    let _ = next_loader;
    todo!("LoadImage(next_loader) then StartImage to chainload the OS loader")
}
