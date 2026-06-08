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
        let meta = store.load_metadata()?;

        Ok(IoConfig::AesXts {
            key1: meta.fvek_key1,
            key2: meta.fvek_key2,
            offset_sector: store.offset_sector(),
            encrypted_offset: EncryptedOffset {
                sector: meta.encrypted_offset,
                total_sectors: store.data_sector_count(),
            },
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

/// TODO(sample): verify the requestor token is a member of
/// BUILTIN\Administrators (SeTokenIsAdmin / RtlCheckTokenMembership).
fn require_administrator(ctx: &IoctlAuthContext<'_>) -> VckResult<()> {
    let _ = ctx;
    Err(VckError::PermissionDenied(
        "administrator privilege required",
    ))
}
