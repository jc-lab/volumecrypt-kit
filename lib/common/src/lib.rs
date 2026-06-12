// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Common types, errors, JVCK metadata format, and loader→driver handover
//! helpers shared across the kernel driver, the UEFI loader, and host tooling.
//!
//! The crate is `no_std` by default (kernel/UEFI). Enabling the `std` feature
//! (the default for host test crates such as `sample/crypto-test`) builds it
//! against `std` while still going through the `alloc` API surface.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod cpu;
pub mod error;
pub mod handover;
pub mod ioctl;
pub mod jvck;
pub mod rng;
pub mod store;
pub mod types;
pub mod xts;

pub use error::{VckError, VckResult};
pub use rng::{set_random_source, RandomSource};
pub use store::{EncryptedOffsetStore, SectorIo};
pub use types::{EncryptedOffset, Guid, SectorRange, VolumeId};
pub use xts::XtsVolumeCipher;
