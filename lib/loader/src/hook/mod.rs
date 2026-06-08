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
    /// Saved `EFI_BLOCK_IO_PROTOCOL` hook state (original `ReadBlocks`, vtable ptr).
    block_io: Option<block_io::BlockIoHook>,
    /// Saved `EFI_BLOCK_IO2_PROTOCOL` hook state (original `ReadBlocksEx`, vtable ptr).
    block_io2: Option<block_io2::BlockIo2Hook>,
}

impl BlockIoHookEngine {
    /// Creates an engine bound to the given crypto/geometry state.
    pub fn new(crypto: LoaderCrypto) -> Self {
        Self {
            crypto,
            block_io: None,
            block_io2: None,
        }
    }

    /// Locates the target volume's Block IO protocol(s), saves the original
    /// read function pointers, and replaces the vtable entries with our hooks.
    ///
    /// Matching is done by GPT partition GUID (carried by the handover payload /
    /// loader config). Both `EFI_BLOCK_IO_PROTOCOL` and (when present)
    /// `EFI_BLOCK_IO2_PROTOCOL` are hooked.
    pub fn install(&mut self) -> VckResult<()> {
        // TODO(loader): LocateHandleBuffer(EFI_BLOCK_IO_PROTOCOL), enumerate
        // handles, open Device Path / Partition Info, match partition GUID,
        // then call block_io::BlockIoHook::install / block_io2::BlockIo2Hook::install
        // to save originals and patch the vtables. Store the results in
        // self.block_io / self.block_io2.
        let _ = &self.crypto;
        todo!("install Block IO / Block IO2 read hooks for the target partition")
    }

    /// Restores all hooked vtables to their original function pointers.
    ///
    /// Must be called before chainloading so the next loader sees pristine
    /// Block IO protocols.
    pub fn uninstall(&mut self) -> VckResult<()> {
        // TODO(loader): restore original ReadBlocks/ReadBlocksEx pointers from
        // self.block_io / self.block_io2 and drop the saved state.
        let _ = (&mut self.block_io, &mut self.block_io2);
        todo!("restore original Block IO / Block IO2 read function pointers")
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
        // TODO(loader): iterate sectors; for each absolute `lba`:
        //   1. if lba < offset_sector (metadata/header region) -> passthrough;
        //   2. rel = lba - offset_sector;
        //   3. if rel is beyond the data region (footer metadata) -> passthrough;
        //   4. if self.crypto.encrypted_offset.is_encrypted(rel) -> AES-XTS
        //      decrypt the sector using key1/key2 with the sector tweak = rel;
        //   5. else -> passthrough.
        let _ = (lba, sector_size, buf, &self.crypto);
        todo!("per-sector AES-XTS decryption decision after original read")
    }
}
