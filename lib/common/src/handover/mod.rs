// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Loader→driver handover payload (framework side).
//!
//! The UEFI loader publishes the handover as a UEFI runtime variable
//! (`SetVariable`, RUNTIME_ACCESS) whose value is the raw msgpack payload; the
//! driver reads it with `ExGetFirmwareEnvironmentVariable`. This module provides
//! only the generic mechanism — the [`payload::HandoverPayload`] trait and the
//! msgpack encode/decode helpers.
//!
//! The concrete payload type **and** the UEFI variable name/GUID it lives under
//! are defined by the integrator (see the sample's `VckHandoverPayload`, which
//! supplies `HandoverPayload::VAR_NAME` / `VAR_GUID`).

pub mod payload;
