// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! `vck-sample-loader` — sample UEFI loader built on `vck-loader`.
//!
//! Drives the loader flow directly with the `vck-loader` building blocks (the
//! framework owns no crypto policy):
//!   1. `vck_loader::init()` — start banner + enable SSE/XMM control bits;
//!   2. read `vck.json` (VMK + next OS loader path + OS partition GUID);
//!   3. open the OS volume Block IO and decrypt the footer metadata OURSELVES —
//!      this sample chooses the JVCK format (AES-256-CBC metadata) and AES-256-XTS
//!      as the volume cipher;
//!   4. install the transparent Block IO decrypt hook (handing it the cipher);
//!   5. publish the ACPI/UEFI-variable handover for the driver;
//!   6. chainload the next OS loader.
//!
//! See docs/architecture.md "sample/loader" and "시스템 볼륨 부팅 흐름".

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;

use uefi::prelude::*;
use vck_common::jvck::store::locate_block_io_volume;
use vck_common::jvck::{JvckCbcCodec, JvckMetadataReader, MetadataCodec};
use vck_common::types::{EncryptedOffset, Guid};
use vck_common::{StaticCipherSupplier, VckResult, VolumeCipherSupplier};
use vck_loader::{BlockIoHookEngine, HookGeometry};
use vck_sample_common::{VckConfig, VckHandoverPayload};

/// UEFI application entry point (uefi 0.37 `#[entry]`).
#[entry]
fn efi_main() -> Status {
    let _ = uefi::helpers::init();
    log::info!("efi_main: entered");

    match run() {
        Ok(()) => {
            log::warn!("chainloaded image returned unexpectedly");
            Status::SUCCESS
        }
        Err(err) => {
            log::error!("boot failed: {err}");
            Status::LOAD_ERROR
        }
    }
}

/// Drive the loader flow. On success control passes to the chained image and
/// this does not return.
fn run() -> VckResult<()> {
    vck_loader::init();

    // Read VMK + the next OS loader path + OS partition GUID from (EFI)/vck.json.
    let config = VckConfig::load_from_esp()?;
    let payload = VckHandoverPayload {
        partition_guid: config.partition_guid,
        vmk: config.vmk.clone(),
    };
    let next_loader = config.osloader_device_path()?;

    // Open + decrypt the footer metadata ourselves and install the transparent
    // decrypt hook. Best-effort: before first-time encryption the footer does not
    // exist yet (the volume is still plaintext), so we skip the hook and still
    // publish the handover + chainload. This also isolates the handover path for
    // validation independently of the crypto machinery.
    if let Err(err) = install_decrypt_hook(config.partition_guid, &config.vmk) {
        log::warn!("decrypt hook skipped: {err}");
    }

    vck_loader::handover::install_handover(&payload)?;
    log::info!("handover published (EfiRuntimeServicesData + locator variable)");
    vck_loader::chainload::chainload_next(&next_loader)
}

/// Open the OS volume Block IO, decrypt the JVCK footer metadata with the VMK,
/// build a cipher supplier, and install the Block IO read/write hooks.
///
/// This is the sample's crypto policy: choosing `JvckMetadataStore` (AES-256-CBC
/// EncryptedMetadata) and `StaticCipherSupplier` (AES-256-XTS) here is a sample
/// decision — a vendor reads/decrypts `locate_block_io_volume`'s `SectorIo` with
/// its own format and supplies a different `VolumeCipherSupplier`.
fn install_decrypt_hook(partition_guid: Guid, vmk: &[u8]) -> VckResult<()> {
    let io = locate_block_io_volume(partition_guid)?;
    // Phase A: parse the header without decrypting; Phase B: the codec unseals
    // the CRC-valid replicas. `JvckCbcCodec` is the sample's metadata-cipher
    // choice — the reader/store hardcodes none. A vendor inspects
    // `reader.header()` and passes a different `MetadataCodec`.
    let reader = JvckMetadataReader::open(io)?;
    // The selector runs per CRC-valid replica: pick the codec, unseal, return
    // both. Returning Err skips a replica with bad decrypted / vendor data so the
    // reader tries the next. This sample picks the JVCK suite.
    let store = reader.into_store(vmk, |replica| {
        let codec: Box<dyn MetadataCodec> = Box::new(JvckCbcCodec);
        let unsealed = codec.unseal(replica, vmk)?;
        Ok((codec, unsealed))
    })?;
    let geometry = HookGeometry {
        partition_guid,
        offset_sector: store.offset_sector(),
        encrypted_offset: EncryptedOffset {
            sector: store.load_offset()?,
            total_sectors: store.data_sector_count(),
        },
    };
    let (key1, key2) = store.fvek_keys();
    let cipher_supplier: Box<dyn VolumeCipherSupplier> =
        Box::new(StaticCipherSupplier::new(*key1, *key2));

    // Release the store NOW: it holds the OS volume's `BlockIO` protocol open
    // exclusively (via `locate_block_io_volume`). The hook engine re-opens the
    // SAME handle `open_protocol_exclusive` in `install()`, which fails with
    // ACCESS_DENIED while the store still holds it. The supplier owns only the
    // raw key bytes and `geometry` is owned, so the store is no longer needed.
    drop(store);

    // Leak the engine to a stable 'static address: the hooked read/write
    // routines recover it via a side table keyed by protocol pointer, and the
    // hooks must outlive the chainload (the OS loader keeps reading/writing
    // through them).
    let engine = Box::leak(Box::new(BlockIoHookEngine::new(geometry, cipher_supplier)?));
    engine.install()?;
    log::info!("block io decrypt hook installed");
    Ok(())
}
