// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//! Pluggable EncryptedMetadata cipher ("metadata codec") + per-replica context.
//!
//! `JvckMetadataStore` owns no metadata-cipher policy. Opening is two-phase
//! ([`JvckMetadataReader`](crate::jvck::store::JvckMetadataReader)):
//!
//! 1. **Phase A** parses the plaintext header / geometry without decrypting.
//! 2. **Phase B** iterates the CRC-valid replicas, building a [`ReplicaCtx`] for
//!    each and calling [`MetadataCodec::unseal`] until one succeeds — the sample
//!    decrypts with **its own** algorithm there, with full access to the parsed
//!    header, the raw encrypted blob, and the replica's vendor-specific data.
//!
//! The same codec is retained by the store for ongoing re-seal (`store()` /
//! `store_state()` during the sweep) and recovery (`load_offset`), so the
//! abstraction is two-directional ([`seal`](MetadataCodec::seal) +
//! [`unseal`](MetadataCodec::unseal)).
//!
//! The default JVCK suite ([`JvckCbcCodec`]) is AES-256-CBC + HKDF-SHA256 + HMAC;
//! a vendor keeps the JVCK container (replicas, salt, HMAC layout) and swaps the
//! inner cipher, selecting it from the header (`vendor_id` / `vendor_version` /
//! `vendor_reserved`) and/or the vendor-specific data region.

use alloc::boxed::Box;

use crate::jvck::metadata::{
    self, JvckHeader, JvckSecrets, ENCRYPTED_METADATA_SIZE, METADATA_BLOCK_SIZE,
    OFF_ENCRYPTED_METADATA, OFF_SALT, OFF_VOLUME_ID, SALT_SIZE,
};
use crate::store::SectorIo;
use crate::types::VolumeState;
use crate::{VckError, VckResult};

/// What [`MetadataCodec::unseal`] recovers from one replica's EncryptedMetadata.
pub struct Unsealed {
    pub encrypted_offset: u64,
    pub state: VolumeState,
    pub secrets: JvckSecrets,
}

/// A single CRC-valid metadata replica handed to [`MetadataCodec::unseal`].
///
/// Exposes the parsed plaintext header, the raw 512-byte block (and the inner
/// encrypted blob / salt / volume id within it), and sector-granular reads of
/// THIS replica's vendor-specific data region — everything a vendor needs to
/// decide and run its metadata decryption.
pub struct ReplicaCtx<'a> {
    header: &'a JvckHeader,
    /// Owned so the ctx can be returned from `JvckMetadataReader::replica_ctx`
    /// while only borrowing the header + io.
    block: [u8; METADATA_BLOCK_SIZE],
    io: &'a dyn SectorIo,
    /// Base LBA of this replica's vendor-specific data region.
    vendor_base_lba: u64,
    /// Sectors available in this replica's vendor-specific data region.
    vendor_sector_count: u64,
    sector_size: u32,
    /// Index of this replica (header replicas first, then footer replicas).
    replica_index: usize,
}

impl<'a> ReplicaCtx<'a> {
    /// Construct a context for one replica. Called by the framework
    /// (`JvckMetadataReader`); samples receive a `&ReplicaCtx`, not build one.
    pub(crate) fn new(
        header: &'a JvckHeader,
        block: [u8; METADATA_BLOCK_SIZE],
        io: &'a dyn SectorIo,
        vendor_base_lba: u64,
        vendor_sector_count: u64,
        sector_size: u32,
        replica_index: usize,
    ) -> Self {
        Self {
            header,
            block,
            io,
            vendor_base_lba,
            vendor_sector_count,
            sector_size,
            replica_index,
        }
    }

    /// The parsed plaintext header (same for every replica of a volume).
    pub fn header(&self) -> &JvckHeader {
        self.header
    }

    /// The full 512-byte Metadata block (CRC already verified).
    pub fn block(&self) -> &[u8] {
        &self.block
    }

    /// The 128-byte EncryptedMetadata blob within the block.
    pub fn encrypted_metadata(&self) -> &[u8] {
        &self.block[OFF_ENCRYPTED_METADATA..OFF_ENCRYPTED_METADATA + ENCRYPTED_METADATA_SIZE]
    }

    /// The per-write salt (plaintext) used to derive this replica's keys.
    pub fn salt(&self) -> &[u8] {
        &self.block[OFF_SALT..OFF_SALT + SALT_SIZE]
    }

    /// The volume id (plaintext) from the header bytes.
    pub fn volume_id(&self) -> [u8; 16] {
        self.block[OFF_VOLUME_ID..OFF_VOLUME_ID + 16]
            .try_into()
            .unwrap()
    }

    /// 0-based index of this replica (header replicas first, then footer).
    pub fn replica_index(&self) -> usize {
        self.replica_index
    }

    /// Sectors available in this replica's vendor-specific data region.
    pub fn vendor_data_sector_count(&self) -> u64 {
        self.vendor_sector_count
    }

    /// Read `buf` (a whole number of sectors) from THIS replica's
    /// vendor-specific data region, starting at vendor-relative `rel_sector`.
    pub fn read_vendor_data(&self, rel_sector: u64, buf: &mut [u8]) -> VckResult<()> {
        let ss = self.sector_size as usize;
        if ss == 0 || buf.is_empty() || !buf.len().is_multiple_of(ss) {
            return Err(VckError::InvalidData(
                "vendor data buffer must be a non-zero multiple of the sector size",
            ));
        }
        let nsec = (buf.len() / ss) as u64;
        if rel_sector
            .checked_add(nsec)
            .is_none_or(|end| end > self.vendor_sector_count)
        {
            return Err(VckError::ValidationFailed(
                "vendor data range exceeds the replica region",
            ));
        }
        self.io.read_sectors(self.vendor_base_lba + rel_sector, buf)
    }
}

/// Seals/unseals the EncryptedMetadata blob of a JVCK Metadata block.
///
/// `unseal`/`seal` MUST round-trip. The plaintext header fields are written /
/// parsed by the store + [`JvckHeader`]; a codec owns only the 128-byte
/// encrypted payload (FVEK + offset + state) and its authentication.
pub trait MetadataCodec: Send + Sync {
    /// Authenticate + decrypt the EncryptedMetadata of `ctx`'s replica. A wrong
    /// `vmk` (or a replica that does not belong to this codec) must error so the
    /// reader can try the next replica.
    fn unseal(&self, ctx: &ReplicaCtx<'_>, vmk: &[u8]) -> VckResult<Unsealed>;

    /// Serialize `header` + the sensitive `secrets`/`encrypted_offset`/`state`
    /// into a 512-byte `out` block (encrypting the inner payload, computing
    /// auth). `salt` is the per-write random salt.
    #[allow(clippy::too_many_arguments)]
    fn seal(
        &self,
        header: &JvckHeader,
        secrets: &JvckSecrets,
        encrypted_offset: u64,
        state: VolumeState,
        salt: &[u8; SALT_SIZE],
        vmk: &[u8],
        out: &mut [u8; METADATA_BLOCK_SIZE],
    ) -> VckResult<()>;

    /// Read only `encrypted_offset` (recovery scan) without retaining the FVEK.
    /// Default: `unseal` then drop the secrets.
    fn read_offset(&self, ctx: &ReplicaCtx<'_>, vmk: &[u8]) -> VckResult<u64> {
        Ok(self.unseal(ctx, vmk)?.encrypted_offset)
    }
}

/// Default JVCK suite codec: AES-256-CBC EncryptedMetadata, keys derived via
/// HKDF-SHA256 (`Volume ID ‖ salt`), authenticated with HMAC-SHA256. Delegates to
/// the reference functions in [`crate::jvck::metadata`] (which operate on the
/// full 512-byte block).
pub struct JvckCbcCodec;

impl MetadataCodec for JvckCbcCodec {
    fn unseal(&self, ctx: &ReplicaCtx<'_>, vmk: &[u8]) -> VckResult<Unsealed> {
        let (encrypted_offset, state, secrets) = metadata::decrypt_payload(ctx.block(), vmk)?;
        Ok(Unsealed {
            encrypted_offset,
            state,
            secrets,
        })
    }

    fn seal(
        &self,
        header: &JvckHeader,
        secrets: &JvckSecrets,
        encrypted_offset: u64,
        state: VolumeState,
        salt: &[u8; SALT_SIZE],
        vmk: &[u8],
        out: &mut [u8; METADATA_BLOCK_SIZE],
    ) -> VckResult<()> {
        header.encode(secrets, encrypted_offset, state, salt, vmk, out)
    }

    fn read_offset(&self, ctx: &ReplicaCtx<'_>, vmk: &[u8]) -> VckResult<u64> {
        metadata::read_encrypted_offset(ctx.block(), vmk)
    }
}

/// Convenience: the default JVCK codec as a boxed trait object.
pub fn default_codec() -> Box<dyn MetadataCodec> {
    Box::new(JvckCbcCodec)
}
