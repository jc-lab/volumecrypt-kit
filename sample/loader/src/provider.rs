// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Sample `LoaderProvider` implementation.
//!
//! Reproduces the ARCH.md "sample/loader" `on_init` flow:
//! read `vck.json`, open the OS volume footer metadata over Block IO and
//! decrypt it with the VMK, build the minimal handover payload (partition_guid
//! + vmk only — FVEK is NOT carried in the payload), and return a
//! [`LoaderConfig`] whose `crypto` drives transparent decryption in the loader.

use vck_common::types::EncryptedOffset;
use vck_common::VckResult;
use vck_loader::{LoaderConfig, LoaderCrypto, LoaderProvider};
use vck_sample_common::VckHandoverPayload;

// NOTE: these cross-crate symbols are owned by the parent (lib/common JVCK
// module + sample/common config). Paths below match ARCH.md symbol names; the
// exact module path may need adjustment once the parent lands them.
// TODO(loader): confirm `vck_common::jvck::JvckMetadataStore` module path and
// `vck_sample_common::VckConfig` import path.
use vck_common::jvck::store::open_volume_footer_uefi;
use vck_sample_common::VckConfig;

/// Sample loader provider. Selects the JVCK default metadata format and the
/// high-level AES-XTS transparent decryption path.
pub struct VckLoaderProvider;

impl LoaderProvider for VckLoaderProvider {
    type Payload = VckHandoverPayload;

    fn on_init(&self) -> VckResult<LoaderConfig<Self::Payload>> {
        // 1. Read VMK and the next OS loader path from (EFI)/vck.json.
        let config = VckConfig::load_from_esp()?;

        // 2. The handover carries only the VMK and partition_guid. The driver
        //    re-decrypts the footer metadata with the VMK to recover the FVEK /
        //    encrypted_offset / geometry.
        let payload = VckHandoverPayload {
            partition_guid: config.partition_guid,
            vmk: config.vmk.clone(),
        };
        let next_loader = config.osloader_device_path()?;

        // 3. Try to open the target OS volume footer metadata with the VMK.
        //
        //    Before first-time encryption the footer metadata does not exist yet
        //    (the volume is still plaintext). In that state there is nothing to
        //    decrypt, so we still publish the handover and chainload — we just
        //    skip the transparent Block IO read hook (`crypto = None`). This also
        //    isolates the ACPI handover path for validation independently of the
        //    crypto machinery.
        let crypto = match open_volume_footer_uefi(config.partition_guid, &config.vmk) {
            Ok(store) => {
                let encrypted_offset = EncryptedOffset {
                    sector: store.load_offset()?,
                    total_sectors: store.data_sector_count(),
                };
                let (key1, key2) = store.fvek_keys();
                let (key1, key2) = (*key1, *key2);
                Some(LoaderCrypto {
                    partition_guid: config.partition_guid,
                    key1,
                    key2,
                    offset_sector: store.offset_sector(),
                    encrypted_offset,
                })
            }
            Err(_) => {
                log::warn!(
                    "vck-loader: no footer metadata yet (volume not encrypted); \
                     publishing handover only"
                );
                None
            }
        };

        Ok(LoaderConfig {
            handover_payload: payload,
            next_loader,
            crypto,
        })
    }
}
