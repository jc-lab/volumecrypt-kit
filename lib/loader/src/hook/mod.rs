// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Block IO hooking engine.
//!
//! See docs/architecture.md "Block IO 후킹 메커니즘". The engine:
//!
//! 1. enumerates Block IO devices via `LocateHandleBuffer(EFI_BLOCK_IO_PROTOCOL)`,
//! 2. matches the target partition by GPT partition GUID,
//! 3. saves the original `ReadBlocks` / `WriteBlocks` function pointers and
//!    replaces the protocol vtable entries with our hooks,
//! 4. on a hooked read, decrypts after the original fills the buffer;
//!    on a hooked write, encrypts a copy of the plaintext before forwarding.
//!
//! Hooked-read decision (all comparisons are in data-region relative sectors):
//!
//! ```text
//! lba in metadata region        -> original read, passthrough (plaintext)
//! rel = lba - offset_sector
//! rel <  encrypted_offset.sector -> original read, then AES-XTS decrypt
//! rel >= encrypted_offset.sector -> original read, passthrough (plaintext)
//! ```
//!
//! Hooked-write decision (symmetric):
//!
//! ```text
//! lba in metadata region        -> passthrough to original write (plaintext)
//! rel = lba - offset_sector
//! rel <  encrypted_offset.sector -> encrypt a copy, then original write
//! rel >= encrypted_offset.sector -> passthrough to original write (plaintext)
//! ```

pub mod block_io;
pub mod block_io2;

use alloc::boxed::Box;
use alloc::vec::Vec;

use vck_common::{VckResult, VolumeCipherSupplier};

use crate::provider::HookGeometry;

/// Installs and removes Block IO read/write hooks for the target volume, and
/// holds the cipher supplier used by the hooked paths.
///
/// The engine owns the saved original function pointers so [`uninstall`] can
/// restore the protocol vtables to their pristine state before chainloading.
///
/// [`uninstall`]: BlockIoHookEngine::uninstall
pub struct BlockIoHookEngine {
    /// Region geometry for transparent encryption/decryption.
    geometry: HookGeometry,
    /// Cipher supplier: produces a short-lived cipher per read/write call.
    /// The default JVCK suite uses [`StaticCipherSupplier`](vck_common::StaticCipherSupplier)
    /// (AES-256-XTS); a RAM-encryption vendor supplies a custom implementation.
    cipher_supplier: Box<dyn VolumeCipherSupplier>,
    /// Saved `EFI_BLOCK_IO_PROTOCOL` hook state (original `ReadBlocks`/`WriteBlocks`, vtable ptr).
    block_io: Option<block_io::BlockIoHook>,
    /// Saved `EFI_BLOCK_IO2_PROTOCOL` hook state (original `ReadBlocksEx`, vtable ptr).
    block_io2: Option<block_io2::BlockIo2Hook>,
}

impl BlockIoHookEngine {
    /// Creates an engine bound to the given geometry and the sample-selected
    /// cipher supplier.
    pub fn new(
        geometry: HookGeometry,
        cipher_supplier: Box<dyn VolumeCipherSupplier>,
    ) -> VckResult<Self> {
        Ok(Self {
            geometry,
            cipher_supplier,
            block_io: None,
            block_io2: None,
        })
    }

    /// Locates the target volume's Block IO protocol(s), saves the original
    /// `ReadBlocks` / `WriteBlocks` function pointers, and replaces the vtable
    /// entries with our hooks.
    ///
    /// Matching is done by GPT partition GUID (carried by the handover payload /
    /// loader config). Both `EFI_BLOCK_IO_PROTOCOL` read and write are hooked.
    pub fn install(&mut self) -> VckResult<()> {
        use alloc::format;
        use uefi::boot::{self, open_protocol_exclusive, SearchType};
        use uefi::proto::media::block::BlockIO;
        use uefi::proto::media::partition::PartitionInfo;
        use vck_common::types::guid_from_windows_bytes;
        use vck_common::VckError;

        let target = self.geometry.partition_guid;
        let engine_ptr: *const BlockIoHookEngine = self;

        let handles = boot::locate_handle_buffer(SearchType::from_proto::<BlockIO>())
            .map_err(|e| VckError::Io(format!("locate BlockIO handles failed: {e:?}")))?;

        for &handle in handles.iter() {
            // Match the target partition by GPT unique GUID via PartitionInfo.
            let matched = match open_protocol_exclusive::<PartitionInfo>(handle) {
                Ok(pinfo) => pinfo
                    .gpt_partition_entry()
                    .map(|gpt| {
                        guid_from_windows_bytes(gpt.unique_partition_guid.to_bytes()) == target
                    })
                    .unwrap_or(false),
                Err(_) => false,
            };
            if !matched {
                continue;
            }

            // Obtain the raw `BlockIoProtocol` instance pointer and patch its
            // `read_blocks` and `write_blocks` fields.
            let mut scoped = open_protocol_exclusive::<BlockIO>(handle)
                .map_err(|e| VckError::Io(format!("open BlockIO for hook failed: {e:?}")))?;
            let proto = scoped
                .get_mut()
                .ok_or(VckError::Io(alloc::string::String::from(
                    "BlockIO interface is null",
                )))? as *mut BlockIO
                as *mut uefi_raw::protocol::block::BlockIoProtocol;

            self.block_io = Some(block_io::BlockIoHook::install(proto, engine_ptr)?);
            // Keep the protocol open (and the patch live) past this scope.
            core::mem::forget(scoped);
            // Block IO2 (async) is not hooked: Windows boot reads the volume via
            // the synchronous Block IO / SimpleFileSystem path. Documented gap.
            return Ok(());
        }

        Err(vck_common::VckError::NotFound(
            "no Block IO partition matched the target GUID for hooking",
        ))
    }

    /// Restores all hooked vtables to their original function pointers.
    ///
    /// NOTE: in the normal boot flow the hooks intentionally remain installed
    /// across the chainload (the OS loader keeps reading/writing through them),
    /// so this is only used for error-path cleanup.
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
    /// multiple of the sector size. A short-lived cipher is acquired once for the
    /// whole call and destroyed immediately after.
    pub(crate) fn decrypt_after_read(
        &self,
        lba: u64,
        sector_size: usize,
        buf: &mut [u8],
    ) -> VckResult<()> {
        if sector_size == 0 {
            return Ok(());
        }
        let mut cipher = match self.cipher_supplier.get_cipher() {
            Some(c) => c,
            None => return Ok(()),
        };
        let offset_sector = self.geometry.offset_sector;
        let total = self.geometry.encrypted_offset.total_sectors;
        for (i, sector) in buf.chunks_mut(sector_size).enumerate() {
            let abs = lba + i as u64;
            let Some(rel) = abs.checked_sub(offset_sector) else {
                continue;
            };
            if rel >= total {
                continue;
            }
            if self.geometry.encrypted_offset.is_encrypted(rel) {
                cipher.decrypt_sector(rel, sector);
            }
        }
        cipher.destroy();
        Ok(())
    }

    /// Shared hooked-write logic: returns an encrypted copy of `buf` to pass to
    /// the original `WriteBlocks`. The caller's buffer is never modified.
    ///
    /// Sectors outside the encrypted region are copied verbatim (plaintext
    /// passthrough). A short-lived cipher is acquired once for the whole call and
    /// destroyed immediately after.
    pub(crate) fn encrypt_before_write(
        &self,
        lba: u64,
        sector_size: usize,
        buf: &[u8],
    ) -> VckResult<Vec<u8>> {
        let mut out = Vec::from(buf);
        if sector_size == 0 {
            return Ok(out);
        }
        let mut cipher = match self.cipher_supplier.get_cipher() {
            Some(c) => c,
            None => return Ok(out),
        };
        let offset_sector = self.geometry.offset_sector;
        let total = self.geometry.encrypted_offset.total_sectors;
        for (i, sector) in out.chunks_mut(sector_size).enumerate() {
            let abs = lba + i as u64;
            let Some(rel) = abs.checked_sub(offset_sector) else {
                continue;
            };
            if rel >= total {
                continue;
            }
            if self.geometry.encrypted_offset.is_encrypted(rel) {
                cipher.encrypt_sector(rel, sector);
            }
        }
        cipher.destroy();
        Ok(out)
    }
}
