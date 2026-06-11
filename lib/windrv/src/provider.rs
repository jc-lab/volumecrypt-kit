// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Core provider interfaces a sample implements.

use alloc::sync::Arc;

use vck_common::{
    handover::payload::HandoverPayload, EncryptedOffset, EncryptedOffsetStore, VckResult, VolumeId,
};
use wdk_sys::{
    ntddk::{PsDereferencePrimaryToken, PsReferencePrimaryToken, SeTokenIsAdmin},
    PACCESS_TOKEN, PEPROCESS,
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

/// The IOCTL requestor's access token, passed to authorization checks.
///
/// Constructed by the driver binary from the requestor process (e.g. via
/// `IoGetRequestorProcess` in the `IRP_MJ_DEVICE_CONTROL` handler). When created
/// with [`AccessToken::from_process`] it holds a primary-token reference that is
/// released on `Drop`, so it stays valid for the lifetime of the borrowing
/// [`IoctlAuthContext`]. All methods require `PASSIVE_LEVEL`.
pub struct AccessToken {
    token: PACCESS_TOKEN,
    /// `true` when we hold a `PsReferencePrimaryToken` reference to release.
    owned: bool,
}

impl AccessToken {
    /// Reference the primary token of `process` (the IOCTL requestor). The
    /// reference is released on `Drop`. Returns `None` if `process` is null or
    /// has no primary token.
    ///
    /// # Safety
    /// `process` must be a valid `PEPROCESS` (or null) and the call must run at
    /// `PASSIVE_LEVEL`.
    pub unsafe fn from_process(process: PEPROCESS) -> Option<Self> {
        if process.is_null() {
            return None;
        }
        let token = PsReferencePrimaryToken(process);
        if token.is_null() {
            return None;
        }
        Some(Self { token, owned: true })
    }

    /// Wrap an already-valid token without taking ownership of its reference
    /// count.
    ///
    /// # Safety
    /// `token` must remain valid for the lifetime of the returned wrapper.
    pub unsafe fn from_raw(token: PACCESS_TOKEN) -> Self {
        Self {
            token,
            owned: false,
        }
    }

    /// The raw `PACCESS_TOKEN`.
    pub fn as_raw(&self) -> PACCESS_TOKEN {
        self.token
    }

    /// Whether the token has the local Administrators group enabled (i.e. the
    /// caller is elevated). Wraps `SeTokenIsAdmin`; must run at `PASSIVE_LEVEL`.
    pub fn is_admin(&self) -> bool {
        // SAFETY: `token` is a valid referenced PACCESS_TOKEN.
        unsafe { SeTokenIsAdmin(self.token) != 0 }
    }
}

impl Drop for AccessToken {
    fn drop(&mut self) {
        if self.owned && !self.token.is_null() {
            // SAFETY: balances the PsReferencePrimaryToken from `from_process`.
            unsafe { PsDereferencePrimaryToken(self.token) };
        }
    }
}

pub struct IoctlAuthContext<'a> {
    pub ioctl_code: u32,
    pub requestor_mode: RequestorMode,
    pub requestor_token: Option<&'a AccessToken>,
}
