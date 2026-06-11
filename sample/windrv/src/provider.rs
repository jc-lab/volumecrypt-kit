//! Sample `VolumeProvider` + IOCTL authorization policy.

use alloc::sync::Arc;

use vck_common::{jvck::JvckMetadataStore, EncryptedOffset, VckError, VckResult};
use vck_driver::{
    io::KernelVolumeIo, ioctl::codes::IOCTL_VCK_GET_PROGRESS, AttachContext, DetachContext,
    IoConfig, IoctlAuthContext, IoctlAuthorization, VolumeProvider,
};
use vck_sample_common::VckHandoverPayload;

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

/// Sample policy: allow the request.
///
/// Access is currently gated at the OS level by the control device's security
/// descriptor (only administrators can open `\\.\VolumeCryptKitSample`). The
/// framework does not yet plumb the requestor token into `IoctlAuthContext`
/// (`requestor_token` is always `None`), so an in-driver membership check is not
/// possible here.
///
/// TODO(sample): for defence-in-depth, create the control device with an
/// admin-only SDDL via `IoCreateDeviceSecure`
/// (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`), and/or plumb the requestor token and use
/// `SeTokenIsAdmin` / `RtlCheckTokenMembership` to enforce per-IOCTL.
fn require_administrator(ctx: &IoctlAuthContext<'_>) -> VckResult<()> {
    let _ = ctx;
    Ok(())
}
