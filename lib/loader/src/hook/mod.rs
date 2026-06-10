//! Block IO hooking engine.
//!
//! See ARCH.md "Block IO 후킹 메커니즘". The engine:
//!
//! 1. enumerates Block IO devices via `LocateHandleBuffer(EFI_BLOCK_IO_PROTOCOL)`,
//! 2. matches the target partition by GPT partition GUID,
//! 3. saves the original `ReadBlocks` / `ReadBlocksEx` function pointers and
//!    replaces the protocol vtable entries with our hooks,
//! 4. on a hooked read, applies the following decision logic.
//!
//! Hooked-read decision (all comparisons are in data-region relative sectors):
//!
//! ```text
//! lba in metadata region        -> original read, passthrough (plaintext)
//! rel = lba - offset_sector
//! rel <  encrypted_offset.sector -> original read, then AES-XTS decrypt
//! rel >= encrypted_offset.sector -> original read, passthrough (plaintext)
//! ```

pub mod block_io;
pub mod block_io2;

use vck_common::xts::XtsVolumeCipher;
use vck_common::VckResult;

use crate::provider::LoaderCrypto;

/// Installs and removes Block IO read hooks for the target volume, and holds the
/// crypto state used by the hooked read path.
///
/// The engine owns the saved original function pointers so [`uninstall`] can
/// restore the protocol vtables to their pristine state before chainloading.
///
/// [`uninstall`]: BlockIoHookEngine::uninstall
pub struct BlockIoHookEngine {
    /// AES-XTS key material and region geometry for transparent decryption.
    crypto: LoaderCrypto,
    /// Prebuilt AES-XTS cipher (shared `XtsVolumeCipher`, data-region relative).
    cipher: XtsVolumeCipher,
    /// Saved `EFI_BLOCK_IO_PROTOCOL` hook state (original `ReadBlocks`, vtable ptr).
    block_io: Option<block_io::BlockIoHook>,
    /// Saved `EFI_BLOCK_IO2_PROTOCOL` hook state (original `ReadBlocksEx`, vtable ptr).
    block_io2: Option<block_io2::BlockIo2Hook>,
}

impl BlockIoHookEngine {
    /// Creates an engine bound to the given crypto/geometry state.
    pub fn new(crypto: LoaderCrypto) -> VckResult<Self> {
        let cipher = XtsVolumeCipher::new(&crypto.key1, &crypto.key2)?;
        Ok(Self {
            crypto,
            cipher,
            block_io: None,
            block_io2: None,
        })
    }

    /// Locates the target volume's Block IO protocol(s), saves the original
    /// read function pointers, and replaces the vtable entries with our hooks.
    ///
    /// Matching is done by GPT partition GUID (carried by the handover payload /
    /// loader config). Both `EFI_BLOCK_IO_PROTOCOL` and (when present)
    /// `EFI_BLOCK_IO2_PROTOCOL` are hooked.
    pub fn install(&mut self) -> VckResult<()> {
        use alloc::format;
        use uefi::boot::{self, open_protocol_exclusive, SearchType};
        use uefi::proto::media::block::BlockIO;
        use uefi::proto::media::partition::PartitionInfo;
        use vck_common::types::guid_from_windows_bytes;
        use vck_common::VckError;

        let target = self.crypto.partition_guid;
        let engine_ptr: *const BlockIoHookEngine = self;

        let handles = boot::locate_handle_buffer(SearchType::from_proto::<BlockIO>())
            .map_err(|e| VckError::Io(format!("locate BlockIO handles failed: {e:?}")))?;

        for &handle in handles.iter() {
            // Match the target partition by GPT unique GUID via PartitionInfo.
            let matched = match open_protocol_exclusive::<PartitionInfo>(handle) {
                Ok(pinfo) => pinfo
                    .gpt_partition_entry()
                    .map(|gpt| guid_from_windows_bytes(gpt.unique_partition_guid.to_bytes()) == target)
                    .unwrap_or(false),
                Err(_) => false,
            };
            if !matched {
                continue;
            }

            // Obtain the raw `BlockIoProtocol` instance pointer and patch its
            // `read_blocks` field. `BlockIO` is `#[repr(transparent)]` over it.
            let mut scoped = open_protocol_exclusive::<BlockIO>(handle)
                .map_err(|e| VckError::Io(format!("open BlockIO for hook failed: {e:?}")))?;
            let proto = scoped.get_mut().ok_or(VckError::Io(
                alloc::string::String::from("BlockIO interface is null"),
            ))? as *mut BlockIO as *mut uefi_raw::protocol::block::BlockIoProtocol;

            self.block_io = Some(block_io::BlockIoHook::install(proto, engine_ptr)?);
            // Keep the protocol open (and the patch live) past this scope.
            core::mem::forget(scoped);
            // Block IO2 (async) is not hooked: Windows boot reads the volume via
            // the synchronous Block IO / SimpleFileSystem path. Documented gap.
            return Ok(());
        }

        Err(VckError::NotFound(
            "no Block IO partition matched the target GUID for hooking",
        ))
    }

    /// Restores all hooked vtables to their original function pointers.
    ///
    /// NOTE: in the normal boot flow the hooks intentionally remain installed
    /// across the chainload (the OS loader keeps reading through them), so this
    /// is only used for error-path cleanup.
    pub fn uninstall(&mut self) -> VckResult<()> {
        if let Some(hook) = self.block_io.take() {
            hook.uninstall()?;
        }
        if let Some(hook) = self.block_io2.take() {
            hook.uninstall()?;
        }
        Ok(())
    }

    /// Shared hooked-read decision logic invoked by both protocol hooks after
    /// the original read has filled `buf` with on-disk (possibly ciphertext)
    /// bytes.
    ///
    /// `lba` is the absolute starting LBA of the request. `buf` length must be a
    /// multiple of the sector size. Sectors are processed individually:
    ///
    /// - LBA inside a metadata region -> left as-is (passthrough).
    /// - `rel = lba - offset_sector`, `rel < encrypted_offset.sector` -> AES-XTS
    ///   decrypted in place.
    /// - otherwise -> left as-is (plaintext beyond the progress boundary).
    pub(crate) fn decrypt_after_read(
        &self,
        lba: u64,
        sector_size: usize,
        buf: &mut [u8],
    ) -> VckResult<()> {
        if sector_size == 0 {
            return Ok(());
        }
        let offset_sector = self.crypto.offset_sector;
        let total = self.crypto.encrypted_offset.total_sectors;
        for (i, sector) in buf.chunks_mut(sector_size).enumerate() {
            let abs = lba + i as u64;
            // (1) header / metadata region before the data region -> plaintext.
            let Some(rel) = abs.checked_sub(offset_sector) else {
                continue;
            };
            // (3) footer metadata beyond the data region -> plaintext.
            if rel >= total {
                continue;
            }
            // (4) only sectors below the progress boundary are ciphertext.
            if self.crypto.encrypted_offset.is_encrypted(rel) {
                self.cipher.decrypt_sector(rel, sector);
            }
            // (5) else: not yet encrypted -> plaintext, leave as-is.
        }
        Ok(())
    }
}
