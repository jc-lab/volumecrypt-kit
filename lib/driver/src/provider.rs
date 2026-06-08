//! Core provider interfaces a sample implements.

use alloc::sync::Arc;

use vck_common::{
    handover::payload::HandoverPayload, EncryptedOffset, EncryptedOffsetStore, VckResult, VolumeId,
};

/// OS Volume boot-time attach callback. Data volumes do not use this (they
/// attach via `IOCTL_JVCK_ATTACH` handled in `ioctl::dispatch`).
///
/// `Payload` is the same `HandoverPayload` type the loader serializes; the
/// framework deserializes the ACPI handover into it and hands it over as a
/// concrete type (no `dyn Any` downcast needed).
pub trait VolumeProvider: Send + Sync + 'static {
    type Payload: HandoverPayload;

    async fn on_attach(&self, ctx: &AttachContext<'_, Self::Payload>) -> VckResult<IoConfig>;
    async fn on_detach(&self, ctx: &DetachContext<'_>) -> VckResult<()>;
}

/// I/O behaviour returned from attach. `offset_sector` is the absolute start LBA
/// of the data region; the engine computes `rel = lba - offset_sector` and
/// passes metadata-region I/O through untouched.
pub enum IoConfig {
    /// Do not attach a filter to this volume.
    Passthrough,
    /// High-level: the framework performs AES-XTS automatically.
    AesXts {
        key1: [u8; 32],
        key2: [u8; 32],
        offset_sector: u64,
        encrypted_offset: EncryptedOffset,
        offset_store: Arc<dyn EncryptedOffsetStore>,
    },
    /// Low-level: the sample drives sector I/O via `IoHooks`.
    Custom {
        io_hooks: Arc<dyn IoHooks>,
        offset_sector: u64,
        encrypted_offset: EncryptedOffset,
        offset_store: Arc<dyn EncryptedOffsetStore>,
    },
}

/// Low-level sector hooks for the `IoConfig::Custom` path. `sector` is
/// data-region relative.
///
/// These are synchronous so the trait stays object-safe behind
/// `Arc<dyn IoHooks>`. A hook that needs to await kernel I/O should drive it to
/// completion internally (e.g. via the `KernelExecutor::block_on`), mirroring
/// the synchronous `SectorIo` used by the encryption sweep.
pub trait IoHooks: Send + Sync + 'static {
    fn read(&self, sector: u64, buf: &mut [u8]) -> VckResult<()>;
    fn write(&self, sector: u64, buf: &[u8]) -> VckResult<()>;
}

pub struct AttachContext<'a, P: HandoverPayload> {
    pub volume_id: &'a VolumeId,
    pub sector_size: u32,
    /// Raw partition capacity in sectors. The data region / footer location is
    /// computed by the provider from metadata.
    pub volume_sectors: u64,
    /// Handover payload, already deserialized into `P`.
    pub handover_data: Option<&'a P>,
}

pub struct DetachContext<'a> {
    pub volume_id: &'a VolumeId,
}

/// IOCTL authorization hook implemented by the sample.
pub trait IoctlAuthorization: Send + Sync + 'static {
    fn authorize(&self, ctx: &IoctlAuthContext<'_>) -> VckResult<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestorMode {
    Kernel,
    User,
}

/// Opaque access token reference passed to authorization checks.
/// TODO(driver): wrap the real `PACCESS_TOKEN` / requestor SID lookup.
pub struct AccessToken {
    _private: (),
}

pub struct IoctlAuthContext<'a> {
    pub ioctl_code: u32,
    pub requestor_mode: RequestorMode,
    pub requestor_token: Option<&'a AccessToken>,
}
