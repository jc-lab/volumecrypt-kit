// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Windows kernel volume filter driver framework.
//!
//! Provides the `VolumeProvider` trait, the filter stack manager, a kernel-only
//! async executor, the progressive-encryption state machine, AES-XTS crypto,
//! and the IOCTL dispatch surface shared with the Go SDK. Samples implement the
//! traits; all mechanism lives here.
#![no_std]

extern crate alloc;

pub mod crypto;
pub mod debug;
pub mod device;
pub mod ntddk_ex;
pub mod executor;
pub mod filter;
pub mod handover;
pub mod io;
pub mod ioctl;
pub mod nt;
pub mod offset;
pub mod provider;
pub mod registry;
pub mod rng;

pub use offset::engine::EncryptionEngine;
pub use provider::{
    global_volume_provider, set_volume_provider, AccessToken, AttachContext, DetachContext,
    IoConfig, IoHooks, IoctlAuthContext, IoctlAuthorization, RequestorMode, VolumeProvider,
};
pub use registry::{
    global_registry, set_global_registry, AttachSource, AttachedVolume, HandoverInfo,
    VolumeAttachRegistry,
};

// Re-export common types so samples depend on a single crate surface.
pub use vck_common::{
    EncryptedOffset, EncryptedOffsetStore, SectorIo, VckError, VckResult, VolumeId,
};
