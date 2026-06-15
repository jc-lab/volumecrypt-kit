// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Shared code for the JVCK sample crates: `vck.json` parsing and the sample's
//! loader→driver handover payload definition (UEFI runtime variable).
#![no_std]

extern crate alloc;

pub mod config;
pub mod payload;

pub use config::{VckConfig, DEFAULT_OSLOADER};
pub use payload::{VckHandoverPayload, HANDOVER_VAR_GUID, HANDOVER_VAR_NAME};
