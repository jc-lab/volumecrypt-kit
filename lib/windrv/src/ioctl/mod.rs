// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! IOCTL surface shared with the Go SDK. `codes` holds the numeric values,
//! `types` the msgpack request/response structs, `dispatch` the handler.

pub mod codes;
pub mod dispatch;
pub mod types;

pub use dispatch::dispatch_ioctl;
