// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Loader→driver handover payload (framework side).
//!
//! The UEFI loader serializes the msgpack payload into a buffer it allocates as
//! `EfiRuntimeServicesData`, and publishes a small [`payload::HandoverLocator`]
//! (the buffer's physical address + length, itself msgpack) in a UEFI runtime
//! variable (`SetVariable`, RUNTIME_ACCESS); the driver reads the locator with
//! `ExGetFirmwareEnvironmentVariable`, then maps the physical buffer
//! (`MmMapIoSpace`) to recover the payload. This module provides only the
//! generic mechanism — the [`payload::HandoverPayload`] trait, the
//! [`payload::HandoverLocator`], and the msgpack encode/decode helpers.
//!
//! The concrete payload type **and** the UEFI variable name/GUID it lives under
//! are defined by the integrator (see the sample's `VckHandoverPayload`, which
//! supplies `HandoverPayload::VAR_NAME` / `VAR_GUID`).

pub mod payload;
