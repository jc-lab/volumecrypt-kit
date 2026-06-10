//! Chainloading the next EFI image.
//!
//! Loads and starts the next OS loader (e.g. the Windows Boot Manager,
//! `msbootmgfw.os.efi`) using `LoadImage` / `StartImage`. See ARCH.md boot flow
//! step 5.

use alloc::format;

use uefi::boot::{image_handle, load_image, start_image, LoadImageSource};
use uefi::proto::BootPolicy;
use vck_common::{VckError, VckResult};

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
    let image = load_image(
        image_handle(),
        LoadImageSource::FromDevicePath {
            // `next_loader` is our owned `Box<DevicePath>`; deref to the borrowed
            // `&uefi::proto::device_path::DevicePath` the FFI source expects.
            device_path: &**next_loader,
            boot_policy: BootPolicy::ExactMatch,
        },
    )
    .map_err(|e| VckError::Io(format!("LoadImage(next loader) failed: {e:?}")))?;

    start_image(image).map_err(|e| VckError::Io(format!("StartImage(next loader) failed: {e:?}")))?;
    Ok(())
}
