//! Control device object + user-space symbolic link.
//!
//! Creates `\Device\VolumeCryptKitSample` and `\DosDevices\VolumeCryptKitSample`
//! so the Go SDK can `CreateFile(\\.\VolumeCryptKitSample)`.

use vck_common::VckResult;

pub const DEVICE_NAME: &str = r"\Device\VolumeCryptKitSample";
pub const SYMLINK_NAME: &str = r"\DosDevices\VolumeCryptKitSample";

pub struct ControlDevice {
    // TODO(driver): hold PDEVICE_OBJECT for the control device.
    _private: (),
}

impl ControlDevice {
    /// Create the control device object and its symbolic link.
    pub fn create() -> VckResult<Self> {
        todo!("IoCreateDevice + IoCreateSymbolicLink")
    }

    /// Delete the symbolic link and device object.
    pub fn destroy(self) -> VckResult<()> {
        todo!("IoDeleteSymbolicLink + IoDeleteDevice")
    }
}
