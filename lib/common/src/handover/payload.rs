// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

use alloc::{string::ToString, vec::Vec};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

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
    messagepack_serde::to_vec(payload)
        .map_err(|err| crate::VckError::MsgpackEncode(err.to_string()))
}

pub fn decode_payload<P: HandoverPayload>(bytes: &[u8]) -> VckResult<P> {
    messagepack_serde::from_slice(bytes)
        .map_err(|err| crate::VckError::MsgpackDecode(err.to_string()))
}

/// Magic stamped into a [`HandoverLocator`] for sanity validation
/// (`b"VCKL"` interpreted little-endian).
pub const HANDOVER_LOCATOR_MAGIC: u32 = u32::from_le_bytes(*b"VCKL");

/// Current [`HandoverLocator`] layout version.
pub const HANDOVER_LOCATOR_VERSION: u16 = 1;

/// Pointer to the handover payload, stored in the UEFI variable.
///
/// Rather than carrying the (potentially large, VMK-bearing) msgpack payload in
/// the UEFI variable value directly, the loader serializes the payload into a
/// buffer it allocates as `EfiRuntimeServicesData` and publishes only this
/// small locator — itself msgpack — in the variable. The driver reads the
/// locator, then maps the physical buffer to recover the payload.
///
/// `address` is the **physical** address of the payload buffer. In the loader's
/// pre-`ExitBootServices` environment memory is identity-mapped, so the pointer
/// returned by `allocate_pool` equals the physical address; the firmware keeps
/// `EfiRuntimeServicesData` pages reserved across the handoff to the OS, so the
/// driver can map that same physical address at runtime (`MmMapIoSpace`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoverLocator {
    /// [`HANDOVER_LOCATOR_MAGIC`].
    pub magic: u32,
    /// [`HANDOVER_LOCATOR_VERSION`].
    pub version: u16,
    /// Physical address of the `EfiRuntimeServicesData` payload buffer.
    pub address: u64,
    /// Byte length of the msgpack payload at `address`.
    pub length: u64,
}

impl HandoverLocator {
    /// Build a current-version locator for a payload buffer.
    pub fn new(address: u64, length: u64) -> Self {
        Self {
            magic: HANDOVER_LOCATOR_MAGIC,
            version: HANDOVER_LOCATOR_VERSION,
            address,
            length,
        }
    }

    /// Validate the magic/version and a non-empty, plausibly-addressed buffer.
    pub fn validate(&self) -> VckResult<()> {
        if self.magic != HANDOVER_LOCATOR_MAGIC {
            return Err(crate::VckError::InvalidData("handover locator: bad magic"));
        }
        if self.version != HANDOVER_LOCATOR_VERSION {
            return Err(crate::VckError::InvalidData(
                "handover locator: unsupported version",
            ));
        }
        if self.address == 0 || self.length == 0 {
            return Err(crate::VckError::InvalidData(
                "handover locator: empty address/length",
            ));
        }
        Ok(())
    }
}

pub fn encode_locator(locator: &HandoverLocator) -> VckResult<Vec<u8>> {
    messagepack_serde::to_vec(locator)
        .map_err(|err| crate::VckError::MsgpackEncode(err.to_string()))
}

pub fn decode_locator(bytes: &[u8]) -> VckResult<HandoverLocator> {
    let locator: HandoverLocator = messagepack_serde::from_slice(bytes)
        .map_err(|err| crate::VckError::MsgpackDecode(err.to_string()))?;
    locator.validate()?;
    Ok(locator)
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

    #[test]
    fn locator_round_trip() {
        let locator = HandoverLocator::new(0x1_2345_6000, 4096);
        let bytes = encode_locator(&locator).expect("encode locator");
        let decoded = decode_locator(&bytes).expect("decode locator");
        assert_eq!(decoded, locator);
    }

    #[test]
    fn locator_rejects_bad_magic() {
        let mut locator = HandoverLocator::new(0x1000, 16);
        locator.magic ^= 0xFFFF_FFFF;
        let bytes = encode_locator(&locator).expect("encode locator");
        assert!(decode_locator(&bytes).is_err());
    }

    #[test]
    fn locator_rejects_empty() {
        let locator = HandoverLocator::new(0, 0);
        let bytes = encode_locator(&locator).expect("encode locator");
        assert!(decode_locator(&bytes).is_err());
    }
}
