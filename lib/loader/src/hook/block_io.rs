// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! `EFI_BLOCK_IO_PROTOCOL` hooking (`ReadBlocks` + `WriteBlocks`).
//!
//! Saves the original `ReadBlocks` and `WriteBlocks` function pointers, patches
//! the protocol instance's vtable fields with [`hooked_read_blocks`] /
//! [`hooked_write_blocks`], and restores them on uninstall.
//!
//! - Read hook: calls the original read to fill the buffer, then decrypts in
//!   place via [`BlockIoHookEngine::decrypt_after_read`].
//! - Write hook: encrypts a copy of the caller's buffer via
//!   [`BlockIoHookEngine::encrypt_before_write`], then forwards the encrypted
//!   copy to the original write (the caller's buffer is left unchanged).
//!
//! `EFI_BLOCK_IO_PROTOCOL` keeps its function pointers inline in the protocol
//! struct (there is no separate vtable), so "patching the vtable" means writing
//! the `read_blocks` / `write_blocks` fields of the firmware's protocol instance.
//!
//! UNTESTED: the patch + `efiapi` callback path must be validated by an actual
//! VM boot (Stage 3h). The crypto decision it calls is covered by host logic.

use core::cell::UnsafeCell;
use core::ffi::c_void;

use uefi::Status;
use uefi_raw::protocol::block::{BlockIoProtocol, Lba};
use vck_common::{VckError, VckResult};

use crate::hook::BlockIoHookEngine;

type ReadBlocksFn = unsafe extern "efiapi" fn(
    this: *const BlockIoProtocol,
    media_id: u32,
    lba: Lba,
    buffer_size: usize,
    buffer: *mut c_void,
) -> Status;

type WriteBlocksFn = unsafe extern "efiapi" fn(
    this: *mut BlockIoProtocol,
    media_id: u32,
    lba: Lba,
    buffer_size: usize,
    buffer: *const c_void,
) -> Status;

/// One hooked protocol instance: its pointer (lookup key), the saved original
/// `read_blocks` and `write_blocks`, and the engine that owns the crypto state.
#[derive(Clone, Copy)]
struct HookEntry {
    protocol: *const BlockIoProtocol,
    original_read: ReadBlocksFn,
    original_write: WriteBlocksFn,
    engine: *const BlockIoHookEngine,
}

const MAX_HOOKS: usize = 8;

/// Global side table keyed by protocol pointer. The hooked callbacks (plain
/// `efiapi` functions) recover the original fn pointers + engine from here.
///
/// The loader is single-threaded (before `ExitBootServices`), so access is
/// serialized by control flow; `UnsafeCell` + manual `Sync` documents that.
struct HookTable {
    entries: UnsafeCell<[Option<HookEntry>; MAX_HOOKS]>,
}
unsafe impl Sync for HookTable {}

static HOOK_TABLE: HookTable = HookTable {
    entries: UnsafeCell::new([None; MAX_HOOKS]),
};

/// Find the table slot for `protocol`, if hooked.
unsafe fn find_entry(protocol: *const BlockIoProtocol) -> Option<HookEntry> {
    let entries = &*HOOK_TABLE.entries.get();
    entries
        .iter()
        .flatten()
        .find(|e| e.protocol == protocol)
        .copied()
}

/// Saved state for a single hooked `EFI_BLOCK_IO_PROTOCOL` instance.
pub struct BlockIoHook {
    protocol: *mut BlockIoProtocol,
}

impl BlockIoHook {
    /// Saves the original `ReadBlocks` and `WriteBlocks` pointers for
    /// `protocol`, records the entry, and patches the instance's vtable fields
    /// to [`hooked_read_blocks`] / [`hooked_write_blocks`].
    ///
    /// # Safety
    /// `protocol` must be a live `EFI_BLOCK_IO_PROTOCOL` instance and `engine` a
    /// pointer that outlives the hook (the loader leaks the engine to `'static`).
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn install(
        protocol: *mut BlockIoProtocol,
        engine: *const BlockIoHookEngine,
    ) -> VckResult<Self> {
        unsafe {
            let original_read = (*protocol).read_blocks;
            let original_write = (*protocol).write_blocks;
            let entries = &mut *HOOK_TABLE.entries.get();
            let slot = entries
                .iter_mut()
                .find(|e| e.is_none())
                .ok_or(VckError::Io(alloc::string::String::from(
                    "Block IO hook table is full",
                )))?;
            *slot = Some(HookEntry {
                protocol: protocol as *const BlockIoProtocol,
                original_read,
                original_write,
                engine,
            });
            (*protocol).read_blocks = hooked_read_blocks;
            (*protocol).write_blocks = hooked_write_blocks;
        }
        Ok(Self { protocol })
    }

    /// Restores the original `ReadBlocks` and `WriteBlocks` pointers and
    /// clears the table entry.
    pub fn uninstall(self) -> VckResult<()> {
        unsafe {
            if let Some(entry) = find_entry(self.protocol as *const BlockIoProtocol) {
                (*self.protocol).read_blocks = entry.original_read;
                (*self.protocol).write_blocks = entry.original_write;
                let entries = &mut *HOOK_TABLE.entries.get();
                for slot in entries.iter_mut() {
                    if matches!(slot, Some(e) if core::ptr::eq(e.protocol, self.protocol)) {
                        *slot = None;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Replacement `ReadBlocks` (`EFI_BLOCK_IO_PROTOCOL.ReadBlocks`).
///
/// Calls the saved original read to fill `buffer`, then runs the engine's
/// per-sector AES-XTS decryption decision over the bytes just read.
///
/// # Safety
/// Called by UEFI firmware as an `EFI_BLOCK_IO_PROTOCOL.ReadBlocks` callback.
/// `this` must be a valid `BlockIoProtocol` registered in `HOOK_TABLE`.
/// `buffer` must point to at least `buffer_size` writable bytes.
pub unsafe extern "efiapi" fn hooked_read_blocks(
    this: *const BlockIoProtocol,
    media_id: u32,
    lba: Lba,
    buffer_size: usize,
    buffer: *mut c_void,
) -> Status {
    let Some(entry) = find_entry(this) else {
        return Status::DEVICE_ERROR;
    };

    // 1. Original firmware read fills the buffer with on-disk bytes.
    let status = (entry.original_read)(this, media_id, lba, buffer_size, buffer);
    if status != Status::SUCCESS {
        return status;
    }

    // 2. Decrypt the encrypted sub-range in place (per-sector decision).
    let media = (*this).media;
    if media.is_null() || buffer.is_null() || buffer_size == 0 {
        return status;
    }
    let block_size = (*media).block_size as usize;
    if block_size != 0 && !entry.engine.is_null() {
        let buf = core::slice::from_raw_parts_mut(buffer as *mut u8, buffer_size);
        let engine = &*entry.engine;
        if engine.decrypt_after_read(lba, block_size, buf).is_err() {
            return Status::DEVICE_ERROR;
        }
    }
    status
}

/// Replacement `WriteBlocks` (`EFI_BLOCK_IO_PROTOCOL.WriteBlocks`).
///
/// Encrypts a copy of the caller's plaintext buffer (per-sector decision), then
/// forwards the encrypted copy to the original `WriteBlocks`. The caller's
/// buffer is never modified.
///
/// # Safety
/// Called by UEFI firmware as an `EFI_BLOCK_IO_PROTOCOL.WriteBlocks` callback.
/// `this` must be a valid `BlockIoProtocol` registered in `HOOK_TABLE`.
/// `buffer` must point to at least `buffer_size` readable bytes.
pub unsafe extern "efiapi" fn hooked_write_blocks(
    this: *mut BlockIoProtocol,
    media_id: u32,
    lba: Lba,
    buffer_size: usize,
    buffer: *const c_void,
) -> Status {
    let Some(entry) = find_entry(this as *const BlockIoProtocol) else {
        return Status::DEVICE_ERROR;
    };

    let media = (*this).media;
    if media.is_null() || buffer.is_null() || buffer_size == 0 {
        return (entry.original_write)(this, media_id, lba, buffer_size, buffer);
    }
    let block_size = (*media).block_size as usize;
    if block_size == 0 || entry.engine.is_null() {
        return (entry.original_write)(this, media_id, lba, buffer_size, buffer);
    }

    // Encrypt a copy so the caller's buffer is left as plaintext.
    let src = core::slice::from_raw_parts(buffer as *const u8, buffer_size);
    let engine = &*entry.engine;
    match engine.encrypt_before_write(lba, block_size, src) {
        Err(_) => Status::DEVICE_ERROR,
        Ok(encrypted) => (entry.original_write)(
            this,
            media_id,
            lba,
            encrypted.len(),
            encrypted.as_ptr() as *const c_void,
        ),
        // `encrypted` dropped here; cipher was already destroyed inside encrypt_before_write.
    }
}
