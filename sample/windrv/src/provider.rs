//! Sample `VolumeProvider` + IOCTL authorization policy.

use alloc::sync::Arc;

use vck_common::{jvck::JvckMetadataStore, EncryptedOffset, VckError, VckResult};
use vck_driver::{
    device::ControlDeviceSecurity, io::KernelVolumeIo,
    ioctl::codes::IOCTL_VCK_GET_PROGRESS, AttachContext, DetachContext, IoConfig, IoctlAuthContext,
    IoctlAuthorization, RequestorMode, VolumeProvider,
};
use vck_sample_common::VckHandoverPayload;
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
    type Payload = VckHandoverPayload;

    async fn on_attach(&self, ctx: &AttachContext<'_, VckHandoverPayload>) -> VckResult<IoConfig> {
        // 1. Handover payload (already deserialized by the framework).
        let payload = ctx
            .handover_data
            .ok_or(VckError::NotFound("no handover data"))?;

        // 2. Match the target partition.
        if ctx.volume_id.partition_guid != payload.partition_guid {
            return Ok(IoConfig::Passthrough);
        }

        // 3. Open the volume footer metadata with the VMK and recover keys +
        //    geometry. The same store persists encrypted_offset later.
        let io = KernelVolumeIo::open(ctx.volume_id, ctx.sector_size, ctx.volume_sectors)?;
        let store = JvckMetadataStore::open(io, &payload.vmk)?;
        let encrypted_offset = EncryptedOffset {
            sector: store.load_offset()?,
            total_sectors: store.data_sector_count(),
        };
        let (key1, key2) = store.fvek_keys();

        Ok(IoConfig::AesXts {
            key1: *key1,
            key2: *key2,
            offset_sector: store.offset_sector(),
            encrypted_offset,
            offset_store: Arc::new(store),
        })
    }

    async fn on_detach(&self, _ctx: &DetachContext<'_>) -> VckResult<()> {
        Ok(())
    }
}

impl IoctlAuthorization for VckVolumeProvider {
    fn authorize(&self, ctx: &IoctlAuthContext<'_>) -> VckResult<()> {
        if ctx.ioctl_code == IOCTL_VCK_GET_PROGRESS
            || ctx.ioctl_code == vck_driver::ioctl::codes::IOCTL_VCK_GET_STATUS
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
        _ => Err(VckError::PermissionDenied("administrator privilege required")),
    }
}
