//! Sample `LoaderProvider` implementation.
//!
//! Reproduces the ARCH.md "sample/loader" `on_init` flow:
//! read `vck.json`, open the OS volume footer metadata over Block IO and
//! decrypt it with the VMK, build the minimal handover payload (partition_guid
//! + vmk only — FVEK is NOT carried in the payload), and return a
//! [`LoaderConfig`] whose `crypto` drives transparent decryption in the loader.

use vck_common::types::EncryptedOffset;
use vck_common::VckResult;
use vck_loader::provider::BootServices;
use vck_loader::{LoaderConfig, LoaderCrypto, LoaderProvider};
use vck_sample_common::VckHandoverPayload;

// NOTE: these cross-crate symbols are owned by the parent (lib/common JVCK
// module + sample/common config). Paths below match ARCH.md symbol names; the
// exact module path may need adjustment once the parent lands them.
// TODO(loader): confirm `vck_common::jvck::JvckMetadataStore` module path and
// `vck_sample_common::VckConfig` import path.
use vck_common::jvck::JvckMetadataStore;
use vck_sample_common::VckConfig;

/// Sample loader provider. Selects the JVCK default metadata format and the
/// high-level AES-XTS transparent decryption path.
pub struct VckLoaderProvider;

impl LoaderProvider for VckLoaderProvider {
    type Payload = VckHandoverPayload;

    fn on_init(&self, boot_services: &BootServices) -> VckResult<LoaderConfig<Self::Payload>> {
        // 1. Read VMK and the next OS loader path from (EFI)/vck.json.
        let config = VckConfig::load_from_esp(boot_services)?;

        // 2. Open the target OS volume over Block IO, read a footer metadata
        //    replica, and decrypt it with the VMK.
        let store = JvckMetadataStore::open_volume_footer_uefi(
            boot_services,
            config.partition_guid,
            &config.vmk,
        )?;
        let meta = store.load_metadata()?;

        // 3. The handover carries only the VMK and partition_guid. The driver
        //    re-decrypts the same footer metadata with the VMK to recover the
        //    FVEK / encrypted_offset / geometry.
        let payload = VckHandoverPayload {
            partition_guid: config.partition_guid,
            vmk: config.vmk.clone(),
        };

        // 4. Build the loader's own LoaderCrypto for transparent decryption from
        //    the metadata just read.
        Ok(LoaderConfig {
            handover_payload: payload,
            next_loader: config.osloader_device_path(boot_services)?,
            crypto: Some(LoaderCrypto {
                key1: meta.fvek_key1,
                key2: meta.fvek_key2,
                offset_sector: store.offset_sector(),
                encrypted_offset: EncryptedOffset {
                    sector: meta.encrypted_offset,
                    total_sectors: store.data_sector_count(),
                },
            }),
        })
    }
}
