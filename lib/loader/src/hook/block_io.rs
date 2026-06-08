//! `EFI_BLOCK_IO_PROTOCOL` hooking (`ReadBlocks`).
//!
//! Saves the original `ReadBlocks` function pointer, patches the protocol
//! vtable with [`hooked_read_blocks`], and restores it on uninstall. The hook
//! delegates the actual decryption decision to
//! [`BlockIoHookEngine::decrypt_after_read`](crate::hook::BlockIoHookEngine::decrypt_after_read).

use vck_common::VckResult;

/// Saved state for a single hooked `EFI_BLOCK_IO_PROTOCOL` instance.
pub struct BlockIoHook {
    // TODO(loader): hold raw pointers to the protocol instance and its Media,
    // plus the original ReadBlocks fn pointer so it can be restored and called.
    //
    // protocol:        *mut EFI_BLOCK_IO_PROTOCOL,
    // original_read:   EFI_BLOCK_IO_READ_BLOCKS,
    _private: (),
}

impl BlockIoHook {
    /// Saves the original `ReadBlocks` pointer and installs the hook into the
    /// protocol vtable for the matched partition handle.
    pub fn install(/* protocol handle / pointer */) -> VckResult<Self> {
        // TODO(loader): OpenProtocol(EFI_BLOCK_IO_PROTOCOL), save Read pointer,
        // overwrite the vtable Read slot with hooked_read_blocks.
        todo!("save original ReadBlocks and patch EFI_BLOCK_IO_PROTOCOL vtable")
    }

    /// Restores the original `ReadBlocks` pointer in the protocol vtable.
    pub fn uninstall(self) -> VckResult<()> {
        // TODO(loader): write self.original_read back into the vtable Read slot.
        let _ = self;
        todo!("restore original EFI_BLOCK_IO_PROTOCOL ReadBlocks pointer")
    }
}

/// Replacement `ReadBlocks` (`EFI_BLOCK_IO_PROTOCOL.ReadBlocks`).
///
/// Calls the saved original read to fill the buffer, then runs the engine's
/// per-sector AES-XTS decryption decision. Signature mirrors the EFI ABI:
/// `(This, MediaId, Lba, BufferSize, Buffer) -> Status`.
// TODO(loader): give this the exact `extern "efiapi"` signature and recover the
// owning BlockIoHookEngine from the patched protocol (e.g. via a side table
// keyed by protocol pointer), then call engine.decrypt_after_read(...).
pub extern "efiapi" fn hooked_read_blocks() {
    todo!("hooked EFI_BLOCK_IO_PROTOCOL.ReadBlocks: original read then AES-XTS decrypt")
}
