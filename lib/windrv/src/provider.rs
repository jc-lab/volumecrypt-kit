// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Core provider interfaces a sample implements.
//!
//! The framework owns no full-volume-encryption policy: when a volume below our
//! filter needs to be bound (boot-time OS volume via the ACPI handover, or a
//! data volume via `IOCTL_JVCK_*`), the framework builds an [`AttachContext`]
//! with an owning [`SectorIo`] over the volume's data path and calls the
//! sample's [`VolumeProvider::on_attach`]. The sample reads the metadata (and any
//! vendor-specific data) over that I/O, decrypts it with **its own** chosen
//! algorithm, builds the [`VolumeCipher`], and returns an [`IoConfig`] carrying
//! the cipher + offset store. The framework never decrypts metadata itself.

use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::boxed::Box;
use alloc::sync::Arc;

use vck_common::{
    types::Guid, EncryptedOffset, EncryptedOffsetStore, SectorIo, VckResult, VolumeCipher,
    VolumeId,
};
use wdk_sys::{
    ntddk::{PsDereferencePrimaryToken, PsReferencePrimaryToken, SeTokenIsAdmin},
    PACCESS_TOKEN, PEPROCESS,
};

/// Volume bind policy implemented by the sample.
///
/// Object-safe and synchronous so the framework can call it from a C PnP
/// completion routine (the boot OS-volume mount) as well as the IOCTL dispatch
/// path, via the process-wide pointer installed with [`set_volume_provider`].
pub trait VolumeProvider: Send + Sync + 'static {
    /// Bind a volume below our filter. The sample opens the metadata over
    /// `ctx.io` (which it may also use to read vendor-specific data sectors),
    /// decrypts it with its own algorithm, builds the [`VolumeCipher`], and
    /// returns the [`IoConfig`] — or [`IoConfig::Passthrough`] to leave the
    /// volume untouched. Runs at `PASSIVE_LEVEL`.
    fn on_attach(&self, ctx: &AttachContext<'_>) -> VckResult<IoConfig>;

    /// Called when a bound volume is being detached. Default no-op.
    fn on_detach(&self, ctx: &DetachContext<'_>) -> VckResult<()> {
        let _ = ctx;
        Ok(())
    }
}

/// I/O behaviour returned from [`VolumeProvider::on_attach`]. `offset_sector` is
/// the absolute start LBA of the data region; the engine computes
/// `rel = lba - offset_sector` and passes metadata-region I/O through untouched.
pub enum IoConfig {
    /// Do not attach a filter to this volume.
    Passthrough,
    /// High-level: the framework runs the sample-supplied [`VolumeCipher`] on the
    /// data path and background sweep. `cipher` is `None` for a provisional
    /// (size-hiding, not-yet-keyed) attach, in which case the sweep is idle.
    Encrypted {
        cipher: Option<Box<dyn VolumeCipher>>,
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

impl IoConfig {
    /// The data-region start LBA (0 for passthrough).
    pub fn offset_sector(&self) -> u64 {
        match self {
            IoConfig::Passthrough => 0,
            IoConfig::Encrypted { offset_sector, .. } | IoConfig::Custom { offset_sector, .. } => {
                *offset_sector
            }
        }
    }

    /// The encrypt geometry + offset store for an `Encrypted`/`Custom` config.
    /// `None` for `Passthrough`.
    pub fn geometry(&self) -> Option<(u64, EncryptedOffset, Arc<dyn EncryptedOffsetStore>)> {
        match self {
            IoConfig::Passthrough => None,
            IoConfig::Encrypted {
                offset_sector,
                encrypted_offset,
                offset_store,
                ..
            }
            | IoConfig::Custom {
                offset_sector,
                encrypted_offset,
                offset_store,
                ..
            } => Some((*offset_sector, encrypted_offset.clone(), offset_store.clone())),
        }
    }
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

/// Context for [`VolumeProvider::on_attach`].
pub struct AttachContext<'a> {
    /// Owning sector I/O over the volume's data path (bypasses our own filter).
    /// The sample reads the metadata block + any vendor-specific data through
    /// this and builds its metadata/offset store on top of a clone of it.
    pub io: Arc<dyn SectorIo>,
    /// Unlock secret (VMK) provided by the loader handover or the IOCTL request.
    pub vmk: &'a [u8],
    /// GPT unique partition GUID, when known (boot OS-volume path). `None` for
    /// data-volume IOCTL attaches that are not matched by partition GUID.
    pub partition_guid: Option<Guid>,
}

pub struct DetachContext<'a> {
    pub volume_id: &'a VolumeId,
}

/// Process-wide pointer to the sample's `VolumeProvider`. Set once at
/// `DriverEntry` via [`set_volume_provider`] so the boot OS-volume mount (a C PnP
/// completion routine that only receives a device object) and the IOCTL dispatch
/// path can both reach the sample's bind policy.
static GLOBAL_PROVIDER: AtomicPtr<()> = AtomicPtr::new(null_mut());

/// Record the process-wide provider pointer. `provider` must outlive the driver
/// (a `'static`).
pub fn set_volume_provider(provider: &'static dyn VolumeProvider) {
    // Store the fat pointer behind a 'static box so the vtable half survives.
    let boxed: Box<&'static dyn VolumeProvider> = Box::new(provider);
    GLOBAL_PROVIDER.store(Box::into_raw(boxed).cast(), Ordering::Release);
}

/// Borrow the process-wide provider, if installed.
pub fn global_volume_provider() -> Option<&'static dyn VolumeProvider> {
    let ptr = GLOBAL_PROVIDER.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // Safety: set_volume_provider only ever stores a leaked
        // `Box<&'static dyn VolumeProvider>`.
        Some(*unsafe { &*ptr.cast::<&'static dyn VolumeProvider>() })
    }
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
