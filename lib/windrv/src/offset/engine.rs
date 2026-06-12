// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! `EncryptionEngine`: decides per-sector crypto behaviour and drives the
//! background encrypt/decrypt sweep, persisting progress via the store.

use vck_common::{EncryptedOffset, EncryptedOffsetStore, SectorIo, VckResult};

use crate::crypto::aes_xts::AesXtsCipher;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    Idle,
    Encrypting,
    Decrypting,
    Paused,
}

/// Wire-compatible integer values mirror the Go SDK's `EncryptionState`.
impl EngineState {
    pub fn as_wire(self) -> i32 {
        match self {
            EngineState::Idle => 0,
            EngineState::Encrypting => 1,
            EngineState::Decrypting => 2,
            EngineState::Paused => 3,
        }
    }
}

/// A point-in-time progress snapshot returned to GET_STATUS / GET_PROGRESS.
#[derive(Debug, Clone, Copy)]
pub struct ProgressSnapshot {
    pub encrypted_sector: u64,
    pub total_sectors: u64,
    pub state: EngineState,
}

pub struct EncryptionEngine {
    /// Absolute start LBA of the data region.
    offset_sector: u64,
    /// Progress (data-region relative) + total target sectors.
    encrypted_offset: EncryptedOffset,
    state: EngineState,
}

impl EncryptionEngine {
    pub fn new(offset_sector: u64, encrypted_offset: EncryptedOffset) -> Self {
        Self {
            offset_sector,
            encrypted_offset,
            state: EngineState::Idle,
        }
    }

    /// Map an absolute LBA to a data-region relative sector, or `None` if the
    /// LBA falls in a metadata region (which must be passed through).
    ///
    /// Header regions yield `None` because `lba < offset_sector`; footer regions
    /// yield `None` because the relative sector is `>= total_sectors`.
    pub fn relative(&self, lba: u64) -> Option<u64> {
        lba.checked_sub(self.offset_sector)
            .filter(|rel| *rel < self.encrypted_offset.total_sectors)
    }

    /// Whether the (relative) sector is currently in the encrypted span.
    pub fn is_encrypted(&self, rel: u64) -> bool {
        self.encrypted_offset.is_encrypted(rel)
    }

    /// Current ciphertext boundary (data-region relative).
    pub fn encrypted_boundary(&self) -> u64 {
        self.encrypted_offset.sector
    }

    pub fn state(&self) -> EngineState {
        self.state
    }

    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            encrypted_sector: self.encrypted_offset.sector,
            total_sectors: self.encrypted_offset.total_sectors,
            state: self.state,
        }
    }

    /// Begin (or resume) progressive encryption. No-op if already fully encrypted.
    pub fn start_encrypt(&mut self) {
        if !self.encrypted_offset.is_fully_encrypted() {
            self.state = EngineState::Encrypting;
        } else {
            self.state = EngineState::Idle;
        }
    }

    /// Begin (or resume) progressive decryption. No-op if nothing is encrypted.
    pub fn start_decrypt(&mut self) {
        if self.encrypted_offset.sector > 0 {
            self.state = EngineState::Decrypting;
        } else {
            self.state = EngineState::Idle;
        }
    }

    pub fn pause(&mut self) {
        if matches!(
            self.state,
            EngineState::Encrypting | EngineState::Decrypting
        ) {
            self.state = EngineState::Paused;
        }
    }

    /// Run one batch of the encrypt/decrypt sweep and persist progress.
    ///
    /// Returns `Ok(true)` if more work remains (caller should schedule another
    /// step), `Ok(false)` when the engine reached `Idle`.
    ///
    /// `io` MUST be the raw lower volume device (below this filter), so the
    /// sweep reads plaintext / writes ciphertext without re-entering the filter.
    ///
    /// CRASH-CONSISTENCY (known limitation): a batch writes the ciphertext for
    /// `[boundary, boundary+count)` and only THEN persists the new boundary. A
    /// hard crash (power loss) between those two steps leaves that batch as
    /// ciphertext on disk while the persisted boundary still marks it plaintext;
    /// on resume the sweep would re-encrypt it (double-encryption → corruption of
    /// that one batch). Eliminating this requires hotzone journaling (backing up
    /// the in-flight region so resume can redo it idempotently), which is out of
    /// scope for this sample. Graceful shutdown is handled separately by pausing
    /// the sweep (see `dispatch::pause_all_volumes`) so the boundary stops
    /// advancing before I/O is cut off.
    pub fn progress_step(
        &mut self,
        io: &dyn SectorIo,
        cipher: &AesXtsCipher,
        store: &dyn EncryptedOffsetStore,
        batch_sectors: u64,
    ) -> VckResult<bool> {
        match self.state {
            EngineState::Encrypting => self.encrypt_step(io, cipher, store, batch_sectors),
            EngineState::Decrypting => self.decrypt_step(io, cipher, store, batch_sectors),
            _ => Ok(false),
        }
    }

    fn encrypt_step(
        &mut self,
        io: &dyn SectorIo,
        cipher: &AesXtsCipher,
        store: &dyn EncryptedOffsetStore,
        batch_sectors: u64,
    ) -> VckResult<bool> {
        if self.encrypted_offset.is_fully_encrypted() {
            self.state = EngineState::Idle;
            return Ok(false);
        }
        let sector_size = io.sector_size() as usize;
        let start_rel = self.encrypted_offset.sector;
        let remaining = self.encrypted_offset.total_sectors - start_rel;
        let count = remaining.min(batch_sectors.max(1));

        let mut buf = alloc::vec![0u8; count as usize * sector_size];
        let abs = self.offset_sector + start_rel;
        crate::vck_log!("sweep: enc read abs={} count={}", abs, count);
        io.read_sectors(abs, &mut buf).map_err(|e| {
            crate::vck_log!("sweep: read err: {}", e);
            e
        })?;
        cipher.encrypt_area(&mut buf, sector_size, start_rel);
        crate::vck_log!("sweep: enc write abs={}", abs);
        io.write_sectors(abs, &buf).map_err(|e| {
            crate::vck_log!("sweep: write err: {}", e);
            e
        })?;

        self.encrypted_offset.sector += count;
        crate::vck_log!("sweep: stored boundary={}", self.encrypted_offset.sector);
        store.store(&self.encrypted_offset).map_err(|e| {
            crate::vck_log!("sweep: store err: {}", e);
            e
        })?;
        store.flush()?;

        if self.encrypted_offset.is_fully_encrypted() {
            self.state = EngineState::Idle;
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn decrypt_step(
        &mut self,
        io: &dyn SectorIo,
        cipher: &AesXtsCipher,
        store: &dyn EncryptedOffsetStore,
        batch_sectors: u64,
    ) -> VckResult<bool> {
        if self.encrypted_offset.sector == 0 {
            self.state = EngineState::Idle;
            return Ok(false);
        }
        let sector_size = io.sector_size() as usize;
        let count = self.encrypted_offset.sector.min(batch_sectors.max(1));
        let new_boundary = self.encrypted_offset.sector - count;

        let mut buf = alloc::vec![0u8; count as usize * sector_size];
        let abs = self.offset_sector + new_boundary;
        io.read_sectors(abs, &mut buf)?;
        cipher.decrypt_area(&mut buf, sector_size, new_boundary);
        io.write_sectors(abs, &buf)?;

        self.encrypted_offset.sector = new_boundary;
        store.store(&self.encrypted_offset)?;
        store.flush()?;

        if new_boundary == 0 {
            self.state = EngineState::Idle;
            Ok(false)
        } else {
            Ok(true)
        }
    }
}
