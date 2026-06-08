//! `(EFI)/vck.json` parsing for the sample loader.
//!
//! ```json
//! { "partition_guid": "...", "vmk": "<base64>", "osloader": "/EFI/.../bootmgfw.os.efi" }
//! ```

use alloc::{string::String, vec::Vec};

use vck_common::{types::Guid, VckResult};

pub const DEFAULT_OSLOADER: &str = "/EFI/Microsoft/Boot/msbootmgfw.os.efi";

#[derive(Debug, Clone)]
pub struct VckConfig {
    pub partition_guid: Guid,
    pub vmk: Vec<u8>,
    pub osloader: String,
}

impl VckConfig {
    /// Parse the raw JSON bytes of `vck.json`.
    ///
    /// TODO(sample): pick a `no_std` JSON parser (serde_json needs std) or
    /// switch the on-ESP config to a `no_std`-friendly format; decode the
    /// base64 VMK; default `osloader` to `DEFAULT_OSLOADER` when absent.
    pub fn parse_json(bytes: &[u8]) -> VckResult<Self> {
        let _ = bytes;
        todo!("parse vck.json (no_std JSON) -> VckConfig")
    }

    /// Read and parse `(EFI)/vck.json` from the EFI System Partition.
    #[cfg(feature = "uefi")]
    pub fn load_from_esp() -> VckResult<Self> {
        // TODO(loader): open the ESP volume, read \\vck.json, call parse_json.
        todo!("read (EFI)/vck.json via uefi::fs and parse")
    }

    /// Build the device path of the next OS loader to chainload.
    #[cfg(feature = "uefi")]
    pub fn osloader_device_path(&self) -> VckResult<uefi::proto::device_path::DevicePathBuffer> {
        // TODO(loader): resolve self.osloader (relative to ESP) to a DevicePath.
        todo!("construct next-loader DevicePath from self.osloader")
    }
}
