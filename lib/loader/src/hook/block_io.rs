//! `EFI_BLOCK_IO_PROTOCOL` hooking (`ReadBlocks`).
//!
//! Saves the original `ReadBlocks` function pointer, patches the protocol
//! instance's `read_blocks` field with [`hooked_read_blocks`], and restores it
//! on uninstall. The hook delegates the actual decryption decision to
//! [`BlockIoHookEngine::decrypt_after_read`](crate::hook::BlockIoHookEngine::decrypt_after_read).
//!
//! `EFI_BLOCK_IO_PROTOCOL` keeps its function pointers inline in the protocol
//! struct (there is no separate vtable), so "patching the vtable" means writing
//! the `read_blocks` field of the firmware's protocol instance.
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

/// One hooked protocol instance: its pointer (lookup key), the saved original
/// `read_blocks`, and the engine that owns the crypto state.
#[derive(Clone, Copy)]
struct HookEntry {
    protocol: *const BlockIoProtocol,
    original: ReadBlocksFn,
    engine: *const BlockIoHookEngine,
}

const MAX_HOOKS: usize = 8;

/// Global side table keyed by protocol pointer. The hooked read callback (a
/// plain `efiapi` function) recovers the original read fn + engine from here.
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
    /// Saves the original `ReadBlocks` pointer for `protocol`, records the
    /// (protocol, original, engine) entry, and patches the instance's
    /// `read_blocks` field to [`hooked_read_blocks`].
    ///
    /// # Safety
    /// `protocol` must be a live `EFI_BLOCK_IO_PROTOCOL` instance and `engine` a
    /// pointer that outlives the hook (the loader leaks the engine to `'static`).
    pub fn install(
        protocol: *mut BlockIoProtocol,
        engine: *const BlockIoHookEngine,
    ) -> VckResult<Self> {
        unsafe {
            let original = (*protocol).read_blocks;
            let entries = &mut *HOOK_TABLE.entries.get();
            let slot = entries
                .iter_mut()
                .find(|e| e.is_none())
                .ok_or(VckError::Io(alloc::string::String::from(
                    "Block IO hook table is full",
                )))?;
            *slot = Some(HookEntry {
                protocol: protocol as *const BlockIoProtocol,
                original,
                engine,
            });
            (*protocol).read_blocks = hooked_read_blocks;
        }
        Ok(Self { protocol })
    }

    /// Restores the original `ReadBlocks` pointer and clears the table entry.
    pub fn uninstall(self) -> VckResult<()> {
        unsafe {
            if let Some(entry) = find_entry(self.protocol as *const BlockIoProtocol) {
                (*self.protocol).read_blocks = entry.original;
                let entries = &mut *HOOK_TABLE.entries.get();
                for slot in entries.iter_mut() {
                    if matches!(slot, Some(e) if e.protocol == self.protocol as *const BlockIoProtocol) {
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
pub unsafe extern "efiapi" fn hooked_read_blocks(
    this: *const BlockIoProtocol,
    media_id: u32,
    lba: Lba,
    buffer_size: usize,
    buffer: *mut c_void,
) -> Status {
    let Some(entry) = find_entry(this) else {
        // Not in the table (should not happen) — fail safe with device error.
        return Status::DEVICE_ERROR;
    };

    // 1. Original firmware read fills the buffer with on-disk bytes.
    let status = (entry.original)(this, media_id, lba, buffer_size, buffer);
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
