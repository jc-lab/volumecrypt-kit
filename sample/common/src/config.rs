// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! `(EFI)/vck.json` parsing for the sample loader.
//!
//! ```json
//! { "partition_guid": "...", "vmk": "<base64>", "osloader": "/EFI/.../bootmgfw.os.efi" }
//! ```
//!
//! The loader runs `no_std`, so this module carries a tiny hand-rolled JSON
//! object scanner (flat object, string values only — which is all `vck.json`
//! ever contains, since it is emitted by our own Go app) and a standard base64
//! decoder for the VMK. Both are exercised by host unit tests.

use alloc::{string::String, vec::Vec};

use vck_common::{types::Guid, VckError, VckResult};

pub const DEFAULT_OSLOADER: &str = "/EFI/Microsoft/Boot/msbootmgfw.os.efi";

#[derive(Debug, Clone)]
pub struct VckConfig {
    pub partition_guid: Guid,
    pub vmk: Vec<u8>,
    pub osloader: String,
}

impl VckConfig {
    /// Parse the raw JSON bytes of `vck.json`.
    ///
    /// Recognizes the flat keys `partition_guid` (canonical GUID string), `vmk`
    /// (base64), and `osloader` (path; defaults to [`DEFAULT_OSLOADER`] when
    /// absent). Only string values are supported — the format is fixed and
    /// machine-generated.
    pub fn parse_json(bytes: &[u8]) -> VckResult<Self> {
        let text = core::str::from_utf8(bytes)
            .map_err(|_| VckError::InvalidData("vck.json is not valid UTF-8"))?;
        let obj = JsonObject::parse(text)?;

        let guid_str = obj
            .get("partition_guid")
            .ok_or(VckError::InvalidData("vck.json: missing partition_guid"))?;
        let partition_guid = Guid::parse_str(guid_str)
            .map_err(|_| VckError::InvalidData("vck.json: partition_guid is not a valid GUID"))?;

        let vmk_b64 = obj
            .get("vmk")
            .ok_or(VckError::InvalidData("vck.json: missing vmk"))?;
        let vmk = base64_decode(vmk_b64)?;
        if vmk.is_empty() {
            return Err(VckError::InvalidData("vck.json: vmk is empty"));
        }

        let osloader = obj
            .get("osloader")
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_OSLOADER)
            .into();

        Ok(Self {
            partition_guid,
            vmk,
            osloader,
        })
    }

    /// Read and parse `(EFI)/vck.json` from the EFI System Partition.
    #[cfg(feature = "uefi")]
    pub fn load_from_esp() -> VckResult<Self> {
        use alloc::format;
        use uefi::boot::{get_image_file_system, image_handle};
        use uefi::cstr16;
        use uefi::fs::FileSystem;

        // The loader is launched from the ESP, so its own image file system IS
        // the ESP. `vck.json` lives at the ESP root.
        let sfs = get_image_file_system(image_handle())
            .map_err(|e| VckError::Io(format!("get_image_file_system failed: {e:?}")))?;
        let mut fs = FileSystem::new(sfs);
        let bytes = fs
            .read(cstr16!("\\vck.json"))
            .map_err(|e| VckError::Io(format!("read \\vck.json failed: {e:?}")))?;
        Self::parse_json(&bytes)
    }

    /// Build the device path of the next OS loader to chainload.
    ///
    /// The result is the device path of the partition our loader image was
    /// loaded from (the ESP) with a media `FilePath` node for [`Self::osloader`]
    /// appended — a full device path suitable for `LoadImage`.
    #[cfg(feature = "uefi")]
    pub fn osloader_device_path(
        &self,
    ) -> VckResult<alloc::boxed::Box<uefi::proto::device_path::DevicePath>> {
        use alloc::{boxed::Box, format, string::String, vec::Vec};
        use uefi::boot::{image_handle, open_protocol_exclusive};
        use uefi::proto::device_path::build::{media::FilePath, DevicePathBuilder};
        use uefi::proto::device_path::DevicePath;
        use uefi::proto::loaded_image::LoadedImage;
        use uefi::CString16;

        // Device path of the partition (device) our loader image came from.
        let li = open_protocol_exclusive::<LoadedImage>(image_handle())
            .map_err(|e| VckError::Io(format!("open LoadedImage failed: {e:?}")))?;
        let dev_handle = li.device().ok_or(VckError::Io(String::from(
            "loaded image has no device handle",
        )))?;
        let dev_path = open_protocol_exclusive::<DevicePath>(dev_handle)
            .map_err(|e| VckError::Io(format!("open device DevicePath failed: {e:?}")))?;

        // "/EFI/.../bootmgfw.os.efi" -> "\EFI\...\bootmgfw.os.efi" (UCS-2).
        let mut win_path = String::with_capacity(self.osloader.len());
        for ch in self.osloader.chars() {
            win_path.push(if ch == '/' { '\\' } else { ch });
        }
        let file_name = CString16::try_from(win_path.as_str())
            .map_err(|_| VckError::InvalidData("osloader path is not valid UCS-2"))?;

        // Rebuild: existing device nodes + media FilePath, finalized + boxed.
        let mut buf: Vec<u8> = Vec::new();
        let mut builder = DevicePathBuilder::with_vec(&mut buf);
        for node in dev_path.node_iter() {
            builder = builder
                .push(&node)
                .map_err(|e| VckError::Io(format!("device path push node: {e:?}")))?;
        }
        let full = builder
            .push(&FilePath {
                path_name: &file_name,
            })
            .map_err(|e| VckError::Io(format!("device path push filepath: {e:?}")))?
            .finalize()
            .map_err(|e| VckError::Io(format!("device path finalize: {e:?}")))?;
        Ok::<Box<DevicePath>, VckError>(full.to_boxed())
    }
}

// ---------------------------------------------------------------------------
// Minimal flat-object JSON scanner (string values only)
// ---------------------------------------------------------------------------

/// A flat JSON object decoded as ordered `(key, value)` string pairs.
struct JsonObject {
    entries: Vec<(String, String)>,
}

impl JsonObject {
    fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Parse a flat `{ "k": "v", ... }` object. Only string values are accepted;
    /// any non-string value or nested structure is rejected.
    fn parse(text: &str) -> VckResult<Self> {
        let bytes = text.as_bytes();
        let mut i = skip_ws(bytes, 0);
        if bytes.get(i) != Some(&b'{') {
            return Err(VckError::InvalidData("vck.json: expected '{'"));
        }
        i += 1;
        let mut entries: Vec<(String, String)> = Vec::new();
        loop {
            i = skip_ws(bytes, i);
            match bytes.get(i) {
                Some(b'}') => break,
                Some(b'"') => {}
                _ => return Err(VckError::InvalidData("vck.json: expected key or '}'")),
            }
            let (key, next) = parse_string(bytes, i)?;
            i = skip_ws(bytes, next);
            if bytes.get(i) != Some(&b':') {
                return Err(VckError::InvalidData("vck.json: expected ':'"));
            }
            i = skip_ws(bytes, i + 1);
            if bytes.get(i) != Some(&b'"') {
                return Err(VckError::InvalidData(
                    "vck.json: only string values supported",
                ));
            }
            let (value, next) = parse_string(bytes, i)?;
            entries.push((key, value));
            i = skip_ws(bytes, next);
            match bytes.get(i) {
                Some(b',') => i += 1,
                Some(b'}') => break,
                _ => return Err(VckError::InvalidData("vck.json: expected ',' or '}'")),
            }
        }
        Ok(Self { entries })
    }
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while let Some(&c) = bytes.get(i) {
        if matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
        } else {
            break;
        }
    }
    i
}

/// Parse a JSON string starting at the opening quote `bytes[start] == '"'`.
/// Returns the decoded value and the index just past the closing quote.
fn parse_string(bytes: &[u8], start: usize) -> VckResult<(String, usize)> {
    debug_assert_eq!(bytes.get(start), Some(&b'"'));
    let mut out = String::new();
    let mut i = start + 1;
    while let Some(&c) = bytes.get(i) {
        match c {
            b'"' => return Ok((out, i + 1)),
            b'\\' => {
                i += 1;
                match bytes.get(i) {
                    Some(b'"') => out.push('"'),
                    Some(b'\\') => out.push('\\'),
                    Some(b'/') => out.push('/'),
                    Some(b'n') => out.push('\n'),
                    Some(b'r') => out.push('\r'),
                    Some(b't') => out.push('\t'),
                    Some(b'b') => out.push('\u{08}'),
                    Some(b'f') => out.push('\u{0C}'),
                    Some(b'u') => {
                        // \uXXXX — decode a single BMP code unit (no surrogate
                        // pairing; vck.json values are ASCII in practice).
                        let hex = bytes
                            .get(i + 1..i + 5)
                            .ok_or(VckError::InvalidData("vck.json: truncated \\u escape"))?;
                        let mut cp: u32 = 0;
                        for &h in hex {
                            let d = (h as char)
                                .to_digit(16)
                                .ok_or(VckError::InvalidData("vck.json: bad \\u escape"))?;
                            cp = cp * 16 + d;
                        }
                        out.push(
                            char::from_u32(cp)
                                .ok_or(VckError::InvalidData("vck.json: bad code point"))?,
                        );
                        i += 4;
                    }
                    _ => return Err(VckError::InvalidData("vck.json: bad escape")),
                }
                i += 1;
            }
            _ => {
                // Append the raw UTF-8 byte run up to the next quote/backslash.
                out.push(c as char);
                i += 1;
            }
        }
    }
    Err(VckError::InvalidData("vck.json: unterminated string"))
}

// ---------------------------------------------------------------------------
// Base64 decoder (standard alphabet, with or without '=' padding)
// ---------------------------------------------------------------------------

fn base64_decode(input: &str) -> VckResult<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &c in input.as_bytes() {
        match c {
            b'=' => break,
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => {}
        }
        let v = val(c).ok_or(VckError::InvalidData("vck.json: invalid base64 in vmk"))? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_GUID: &str = "0f77955a-f63e-f111-8b5c-b42e9911840a";

    #[test]
    fn parses_full_config() {
        // base64("\x00\x01\x02\x03") = "AAECAw=="
        let json = r#"{ "partition_guid": "0f77955a-f63e-f111-8b5c-b42e9911840a",
            "vmk": "AAECAw==", "osloader": "/EFI/Microsoft/Boot/bootmgfw.os.efi" }"#;
        let cfg = VckConfig::parse_json(json.as_bytes()).expect("parse");
        assert_eq!(cfg.partition_guid, Guid::parse_str(SAMPLE_GUID).unwrap());
        assert_eq!(cfg.vmk, alloc::vec![0x00, 0x01, 0x02, 0x03]);
        assert_eq!(cfg.osloader, "/EFI/Microsoft/Boot/bootmgfw.os.efi");
    }

    #[test]
    fn osloader_defaults_when_absent() {
        let json = r#"{"partition_guid":"0f77955a-f63e-f111-8b5c-b42e9911840a","vmk":"AAECAw=="}"#;
        let cfg = VckConfig::parse_json(json.as_bytes()).expect("parse");
        assert_eq!(cfg.osloader, DEFAULT_OSLOADER);
    }

    #[test]
    fn base64_decodes_32_byte_vmk() {
        // The fixed sample VMK 00..1f, base64-encoded.
        let b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let bytes = base64_decode(b64).expect("b64");
        let expected: Vec<u8> = (0u8..32).collect();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn rejects_missing_vmk() {
        let json = r#"{"partition_guid":"0f77955a-f63e-f111-8b5c-b42e9911840a"}"#;
        assert!(VckConfig::parse_json(json.as_bytes()).is_err());
    }

    #[test]
    fn rejects_non_string_value() {
        let json = r#"{"partition_guid":"0f77955a-f63e-f111-8b5c-b42e9911840a","vmk":123}"#;
        assert!(VckConfig::parse_json(json.as_bytes()).is_err());
    }
}
