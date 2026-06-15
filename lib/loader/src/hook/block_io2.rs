// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! `EFI_BLOCK_IO2_PROTOCOL` hooking (`ReadBlocksEx`).
//!
//! Mirrors [`block_io`](crate::hook::block_io) but for the asynchronous
//! `EFI_BLOCK_IO2_PROTOCOL`. Saves the original `ReadBlocksEx` pointer, patches
//! the vtable with [`hooked_read_blocks_ex`], and restores it on uninstall.

use vck_common::VckResult;

/// Saved state for a single hooked `EFI_BLOCK_IO2_PROTOCOL` instance.
pub struct BlockIo2Hook {
    // TODO(loader): hold raw pointers to the protocol instance and its Media,
    // plus the original ReadBlocksEx fn pointer so it can be restored/called.
    //
    // protocol:         *mut EFI_BLOCK_IO2_PROTOCOL,
    // original_read_ex: EFI_BLOCK_IO2_READ_BLOCKS_EX,
    _private: (),
}

impl BlockIo2Hook {
    /// Saves the original `ReadBlocksEx` pointer and installs the hook into the
    /// protocol vtable for the matched partition handle.
    pub fn install(/* protocol handle / pointer */) -> VckResult<Self> {
        // TODO(loader): OpenProtocol(EFI_BLOCK_IO2_PROTOCOL), save ReadEx pointer,
        // overwrite the vtable ReadBlocksEx slot with hooked_read_blocks_ex.
        todo!("save original ReadBlocksEx and patch EFI_BLOCK_IO2_PROTOCOL vtable")
    }

    /// Restores the original `ReadBlocksEx` pointer in the protocol vtable.
    pub fn uninstall(self) -> VckResult<()> {
        // TODO(loader): write self.original_read_ex back into the vtable slot.
        let _ = self;
        todo!("restore original EFI_BLOCK_IO2_PROTOCOL ReadBlocksEx pointer")
    }
}

/// Replacement `ReadBlocksEx` (`EFI_BLOCK_IO2_PROTOCOL.ReadBlocksEx`).
///
/// Asynchronous variant: the EFI ABI adds an `EFI_BLOCK_IO2_TOKEN` so the read
/// may complete later. The decryption decision must run after the underlying
/// read has actually completed (e.g. by chaining the token's event), then call
/// the engine's per-sector AES-XTS decision.
// TODO(loader): give this the exact `extern "efiapi"` signature
// `(This, MediaId, Lba, Token, BufferSize, Buffer) -> Status`, hook the token
// completion to run decrypt_after_read before signaling the caller's event.
pub extern "efiapi" fn hooked_read_blocks_ex() {
    todo!("hooked EFI_BLOCK_IO2_PROTOCOL.ReadBlocksEx: original read then AES-XTS decrypt on completion")
}
