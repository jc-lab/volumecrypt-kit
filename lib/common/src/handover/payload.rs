// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

use alloc::{string::ToString, vec::Vec};

use serde::{de::DeserializeOwned, Serialize};

use crate::VckResult;

/// A loader→driver handover payload.
///
/// The associated constants identify the UEFI runtime variable the payload is
/// published under: the loader writes `SetVariable(VAR_NAME, VAR_GUID, ...)` and
/// the driver reads the same variable. They are part of the integrator's
/// contract — see the sample's `VckHandoverPayload` impl — not the framework, so
/// the concrete name/GUID live with the concrete payload type.
pub trait HandoverPayload: Serialize + DeserializeOwned {
    /// UEFI variable name carrying this handover payload (UCS-2 convertible).
    const VAR_NAME: &'static str;
    /// Vendor GUID for [`VAR_NAME`](Self::VAR_NAME), as the 16 raw bytes of a
    /// Windows/UEFI `GUID` (`Data1`/`Data2`/`Data3` little-endian, `Data4` as-is).
    /// Both the loader (`uefi::Guid`) and the driver (`wdk_sys::GUID`) build their
    /// GUID from these same bytes.
    const VAR_GUID: [u8; 16];
}

pub fn encode_payload<P: HandoverPayload>(payload: &P) -> VckResult<Vec<u8>> {
    Ok(messagepack_serde::to_vec(payload)
        .map_err(|err| crate::VckError::MsgpackEncode(err.to_string()))?)
}

pub fn decode_payload<P: HandoverPayload>(bytes: &[u8]) -> VckResult<P> {
    Ok(messagepack_serde::from_slice(bytes)
        .map_err(|err| crate::VckError::MsgpackDecode(err.to_string()))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestPayload {
        partition_guid: [u8; 16],
        vmk: Vec<u8>,
    }

    impl HandoverPayload for TestPayload {
        const VAR_NAME: &'static str = "TestHandover";
        const VAR_GUID: [u8; 16] = [0u8; 16];
    }

    #[test]
    fn encode_decode_round_trip() {
        let original = TestPayload {
            partition_guid: [
                0x5a, 0x95, 0x77, 0x0f, 0x3e, 0xf6, 0x11, 0xf1, 0x8b, 0x5c, 0xb4, 0x2e, 0x99, 0x11,
                0x84, 0x0a,
            ],
            vmk: (0u8..32).collect(),
        };
        let bytes = encode_payload(&original).expect("encode");
        let decoded: TestPayload = decode_payload(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_payload::<TestPayload>(&[0xff, 0x00, 0x12, 0x34]).is_err());
    }
}
