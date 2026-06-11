// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Progressive-encryption offset state machine.

pub mod engine;

pub use engine::{EncryptionEngine, EngineState, ProgressSnapshot};
