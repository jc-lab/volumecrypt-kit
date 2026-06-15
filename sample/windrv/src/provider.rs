// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
// SPDX-FileCopyrightText: 2026, 2026 Copyright (c) JC-Lab All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Sample `VolumeProvider` + IOCTL authorization policy.

use alloc::boxed::Box;
use alloc::sync::Arc;

use vck_common::{
    jvck::{JvckCbcCodec, JvckMetadataReader, MetadataCodec},
    EncryptedOffset, EncryptedOffsetStore, VckError, VckResult, VolumeCipher,
};
use vck_windrv::{
    crypto::AesXtsCipher, device::ControlDeviceSecurity, ioctl::codes::IOCTL_VCK_GET_PROGRESS,
    AttachContext, DetachContext, IoConfig, IoctlAuthContext, IoctlAuthorization, RequestorMode,
    VolumeProvider,
};
use wdk_sys::GUID;

/// Control-device SDDL. Local System (`SY`) and Built-in Administrators (`BA`)
/// get full access (`GA`); Authenticated Users (`AU`) get read+execute only
/// (`GRGX`). A non-admin therefore cannot open the device with write access, so
/// the OS rejects every state-mutating IOCTL (all carry `FILE_WRITE_ACCESS`)
/// before it reaches the driver. Read-only queries (status/progress, which carry
/// `FILE_READ_ACCESS` and are exempt in `authorize`) remain available to
/// non-admins that open the device read-only.
const CONTROL_DEVICE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;AU)";

/// Private device class GUID for the control device, required by
/// `IoCreateDeviceSecure`. `{8F3C1A2B-5D74-4E96-A1B0-2C9E7F46D3A8}`.
const CONTROL_DEVICE_CLASS_GUID: GUID = GUID {
    Data1: 0x8F3C_1A2B,
    Data2: 0x5D74,
    Data3: 0x4E96,
    Data4: [0xA1, 0xB0, 0x2C, 0x9E, 0x7F, 0x46, 0xD3, 0xA8],
};

/// Security configuration applied to the control device at creation time.
pub fn control_device_security() -> ControlDeviceSecurity<'static> {
    ControlDeviceSecurity {
        sddl: CONTROL_DEVICE_SDDL,
        class_guid: CONTROL_DEVICE_CLASS_GUID,
    }
}

pub struct VckVolumeProvider;

impl VolumeProvider for VckVolumeProvider {
    fn on_attach(&self, ctx: &AttachContext<'_>) -> VckResult<IoConfig> {
        // The framework hands us an owning SectorIo over the volume's data path
        // and the VMK; it owns no crypto policy. This sample chooses the JVCK
        // format: open + decrypt the metadata (AES-256-CBC EncryptedMetadata) and
        // recover the FVEK + geometry + persisted progress.
        //
        // Phase A: parse the plaintext header / layout without decrypting.
        let reader = JvckMetadataReader::open(ctx.io.clone())?;
        // A vendor would inspect `reader.header()` (vendor_id / vendor_version /
        // vendor_reserved) and/or `reader.read_vendor_data(..)` here to choose its
        // `MetadataCodec`. This sample fixes the JVCK suite (AES-256-CBC
        // EncryptedMetadata) — the store/reader hardcodes none.
        //
        // Phase B: the selector is called per CRC-valid replica; it picks the
        // codec, unseals, and returns BOTH (the store keeps the codec for re-seal
        // during the sweep). Returning `Err` rejects a replica whose decrypted /
        // vendor data is bad, so the reader tries the next. This sample picks the
        // JVCK suite and accepts the first replica that unseals.
        let vmk = ctx.vmk;
        let store = reader.into_store(vmk, |replica| {
            let codec: Box<dyn MetadataCodec> = Box::new(JvckCbcCodec);
            let unsealed = codec.unseal(replica, vmk)?;
            Ok((codec, unsealed))
        })?;
        let encrypted_offset = EncryptedOffset {
            sector: store.load_offset()?,
            total_sectors: store.data_sector_count(),
        };
        let offset_sector = store.offset_sector();

        // Sample's volume-cipher choice: AES-256-XTS keyed by the recovered FVEK.
        // A vendor returns any other `Box<dyn VolumeCipher>` here instead.
        let (key1, key2) = store.fvek_keys();
        let cipher: Box<dyn VolumeCipher> = Box::new(AesXtsCipher::new(*key1, *key2)?);

        let offset_store: Arc<dyn EncryptedOffsetStore> = Arc::new(store);
        Ok(IoConfig::Encrypted {
            cipher: Some(cipher),
            offset_sector,
            encrypted_offset,
            offset_store,
        })
    }

    fn on_detach(&self, _ctx: &DetachContext<'_>) -> VckResult<()> {
        Ok(())
    }
}

impl IoctlAuthorization for VckVolumeProvider {
    fn authorize(&self, ctx: &IoctlAuthContext<'_>) -> VckResult<()> {
        if ctx.ioctl_code == IOCTL_VCK_GET_PROGRESS
            || ctx.ioctl_code == vck_windrv::ioctl::codes::IOCTL_VCK_GET_STATUS
        {
            return Ok(());
        }
        require_administrator(ctx)
    }
}

/// Require the requestor to be an administrator.
///
/// Two layers enforce this. First, the control device's SDDL (see
/// [`CONTROL_DEVICE_SDDL`], installed via `IoCreateDeviceSecure`) only lets
/// administrators/System open `\\.\VolumeCryptKitSample` with write access, and
/// every state-mutating IOCTL carries `FILE_WRITE_ACCESS`, so the I/O manager
/// rejects non-admins before they reach here. Second, this in-driver check
/// (defence-in-depth) inspects the requestor's primary token with
/// `SeTokenIsAdmin`.
///
/// Kernel-mode requestors (e.g. the driver's own shutdown self-IOCTLs) are
/// trusted and exempt. A user-mode request with no recoverable token is denied.
fn require_administrator(ctx: &IoctlAuthContext<'_>) -> VckResult<()> {
    if ctx.requestor_mode == RequestorMode::Kernel {
        return Ok(());
    }
    match ctx.requestor_token {
        Some(token) if token.is_admin() => Ok(()),
        _ => Err(VckError::PermissionDenied(
            "administrator privilege required",
        )),
    }
}
