// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

use alloc::{string::ToString, vec::Vec};

use serde::{de::DeserializeOwned, Serialize};

use crate::VckResult;

pub trait HandoverPayload: Serialize + DeserializeOwned {
    const ACPI_SIGNATURE: [u8; 4];
    const ACPI_OEM_ID: [u8; 6];
}

pub fn encode_payload<P: HandoverPayload>(payload: &P) -> VckResult<Vec<u8>> {
    Ok(messagepack_serde::to_vec(payload)
        .map_err(|err| crate::VckError::MsgpackEncode(err.to_string()))?)
}

pub fn decode_payload<P: HandoverPayload>(bytes: &[u8]) -> VckResult<P> {
    Ok(messagepack_serde::from_slice(bytes)
        .map_err(|err| crate::VckError::MsgpackDecode(err.to_string()))?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverBlob {
    pub signature: [u8; 4],
    pub oem_id: [u8; 6],
    pub payload: Vec<u8>,
}

impl HandoverBlob {
    pub fn new<P: HandoverPayload>(payload: &P) -> VckResult<Self> {
        Ok(Self {
            signature: P::ACPI_SIGNATURE,
            oem_id: P::ACPI_OEM_ID,
            payload: encode_payload(payload)?,
        })
    }
}
