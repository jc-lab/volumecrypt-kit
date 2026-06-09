//! Volume-backed JVCK metadata store implementing `EncryptedOffsetStore`.
//!
//! Works for both OS and data volumes by reading/writing the header/footer
//! replica regions through a `SectorIo`.
//!
//! Replica layout (all sizes are sector-aligned; `metadata_size` must be a
//! multiple of `sector_size`):
//! - Header replica `i`: region starts at `i * replica_sectors`; the 512-byte
//!   Metadata block occupies the **first** sector of the region (`[Metadata][vendor]`).
//! - Footer replica `j`: occupies the last `use_footer` regions of the volume;
//!   the Metadata block occupies the **last** sector of the region
//!   (`[vendor][Metadata]`), so the final footer replica's Metadata is the very
//!   last sector of the volume and can be found by a single read.

use alloc::vec::Vec;

use crate::{
    jvck::{metadata::JvckMetadata, metadata::METADATA_BLOCK_SIZE, options::JvckMetadataOptions},
    store::{EncryptedOffsetStore, SectorIo},
    types::EncryptedOffset,
    VckError, VckResult,
};

/// Computed geometry of the encryption target region.
#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    /// First absolute LBA of the data (encryptable) region.
    pub offset_sector: u64,
    /// Number of sectors to encrypt (metadata regions excluded).
    pub data_sectors: u64,
    pub sector_size: u32,
}

pub struct JvckMetadataStore<S: SectorIo> {
    io: S,
    options: JvckMetadataOptions,
    vmk: Vec<u8>,
    geometry: Geometry,
    volume_sectors: u64,
    /// Immutable template (keys, volume id, counts). Only `encrypted_offset`
    /// changes at runtime, so `store()` clones this and overrides that field.
    template: JvckMetadata,
}

/// Sectors-per-replica for the given layout.
fn replica_sectors(metadata_size: u32, sector_size: u32) -> u64 {
    (metadata_size / sector_size) as u64
}

/// Absolute LBAs of every replica's Metadata block (header first, then footer).
fn metadata_sector_lbas(
    volume_sectors: u64,
    replica_sectors: u64,
    use_header: u32,
    use_footer: u32,
) -> Vec<u64> {
    let mut lbas = Vec::with_capacity((use_header + use_footer) as usize);
    // Header: Metadata in the first sector of each region.
    for i in 0..use_header as u64 {
        lbas.push(i * replica_sectors);
    }
    // Footer: Metadata in the last sector of each region.
    let footer_start = volume_sectors - use_footer as u64 * replica_sectors;
    for j in 0..use_footer as u64 {
        let region_start = footer_start + j * replica_sectors;
        lbas.push(region_start + replica_sectors - 1);
    }
    lbas
}

fn compute_geometry(
    sector_size: u32,
    volume_sectors: u64,
    options: &JvckMetadataOptions,
) -> VckResult<Geometry> {
    if (sector_size as usize) < METADATA_BLOCK_SIZE {
        return Err(VckError::Unsupported("sector size smaller than 512"));
    }
    if options.metadata_size % sector_size != 0 {
        return Err(VckError::ValidationFailed(
            "metadata_size must be a multiple of sector_size",
        ));
    }
    let rs = replica_sectors(options.metadata_size, sector_size);
    let consumed = (options.use_header + options.use_footer) as u64 * rs;
    if consumed >= volume_sectors {
        return Err(VckError::ValidationFailed(
            "volume too small to hold metadata replicas",
        ));
    }
    Ok(Geometry {
        offset_sector: options.use_header as u64 * rs,
        data_sectors: volume_sectors - consumed,
        sector_size,
    })
}

fn read_block<S: SectorIo>(
    io: &S,
    sector_size: u32,
    lba: u64,
) -> VckResult<[u8; METADATA_BLOCK_SIZE]> {
    let mut sector = alloc::vec![0u8; sector_size as usize];
    io.read_sectors(lba, &mut sector)?;
    let mut block = [0u8; METADATA_BLOCK_SIZE];
    block.copy_from_slice(&sector[..METADATA_BLOCK_SIZE]);
    Ok(block)
}

fn write_block<S: SectorIo>(
    io: &S,
    sector_size: u32,
    lba: u64,
    block: &[u8; METADATA_BLOCK_SIZE],
) -> VckResult<()> {
    // The Metadata block sits alone in its sector (layout is sector-aligned),
    // so zeroing the remainder of the sector cannot clobber vendor data.
    let mut sector = alloc::vec![0u8; sector_size as usize];
    sector[..METADATA_BLOCK_SIZE].copy_from_slice(block);
    io.write_sectors(lba, &sector)
}

fn read_metadata_at<S: SectorIo>(
    io: &S,
    sector_size: u32,
    lba: u64,
    vmk: &[u8],
) -> VckResult<JvckMetadata> {
    let block = read_block(io, sector_size, lba)?;
    JvckMetadata::parse(&block, vmk)
}

/// Read the authoritative metadata to learn the layout (metadata_size, header /
/// footer replica counts) WITHOUT knowing it in advance.
///
/// The volume's very last sector is always a footer Metadata block: the footer
/// region sits at the end of the volume and, within a footer replica, the
/// Metadata block is the last sector (`[vendor][Metadata]`). For header-only
/// layouts (no footer) we fall back to sector 0 (`[Metadata][vendor]`).
fn bootstrap<S: SectorIo>(
    io: &S,
    sector_size: u32,
    volume_sectors: u64,
    vmk: &[u8],
) -> VckResult<JvckMetadata> {
    if volume_sectors == 0 {
        return Err(VckError::NotFound("empty volume"));
    }
    // A `JVCK` signature + valid Header CRC32 is checkable WITHOUT the VMK, so we
    // can tell "blank volume" (-> NotFound, caller may create) apart from
    // "metadata present but wrong VMK / corrupt" (-> propagate the auth error,
    // so the caller never overwrites a real volume).
    for lba in [volume_sectors - 1, 0] {
        let block = read_block(io, sector_size, lba)?;
        if JvckMetadata::verify_crc(&block).is_ok() {
            return JvckMetadata::parse(&block, vmk);
        }
    }
    Err(VckError::NotFound("no JVCK metadata present"))
}

impl<S: SectorIo> JvckMetadataStore<S> {
    /// Open an existing JVCK volume: locate a valid replica (last sector first,
    /// then first sector), authenticate with `vmk`, and compute geometry.
    pub fn open(io: S, vmk: &[u8]) -> VckResult<Self> {
        let sector_size = io.sector_size();
        if (sector_size as usize) < METADATA_BLOCK_SIZE {
            return Err(VckError::Unsupported("sector size smaller than 512"));
        }
        let volume_sectors = io.total_sectors();

        // The layout (metadata_size, replica counts) is read from the volume
        // itself — always available in the last sector (footer Metadata).
        let template = bootstrap(&io, sector_size, volume_sectors, vmk)?;

        let options = JvckMetadataOptions {
            use_header: template.header_replica_count as u32,
            use_footer: template.footer_replica_count as u32,
            metadata_size: template.metadata_size,
        };
        let geometry = compute_geometry(sector_size, volume_sectors, &options)?;
        Ok(Self {
            io,
            options,
            vmk: vmk.to_vec(),
            geometry,
            volume_sectors,
            template,
        })
    }

    /// Initialize a brand new JVCK volume (first-time encryption): lay out the
    /// replicas per `options` and write seed metadata (`encrypted_offset = 0`).
    pub fn create(
        io: S,
        vmk: &[u8],
        options: JvckMetadataOptions,
        fvek_key1: [u8; 32],
        fvek_key2: [u8; 32],
        volume_id: [u8; 16],
    ) -> VckResult<Self> {
        options.validate()?;
        let sector_size = io.sector_size();
        let volume_sectors = io.total_sectors();
        let geometry = compute_geometry(sector_size, volume_sectors, &options)?;

        let template = JvckMetadata {
            vendor_id: 0,
            metadata_version: 1,
            vendor_version: 0,
            metadata_size: options.metadata_size,
            sector_size,
            header_replica_count: options.use_header as u8,
            footer_replica_count: options.use_footer as u8,
            volume_id,
            encrypted_offset: 0,
            fvek_key1,
            fvek_key2,
        };

        let store = Self {
            io,
            options,
            vmk: vmk.to_vec(),
            geometry,
            volume_sectors,
            template,
        };
        store.write_all_replicas(&store.template)?;
        Ok(store)
    }

    /// Read every replica, authenticate with the VMK, and return the most
    /// up-to-date metadata. Recovery policy: among valid replicas, pick the one
    /// with the largest `encrypted_offset`.
    pub fn load_metadata(&self) -> VckResult<JvckMetadata> {
        let sector_size = self.geometry.sector_size;
        // Re-read the layout from the last sector every time so metadata_size /
        // replica counts come from the volume, not a possibly-stale cache.
        let boot = bootstrap(&self.io, sector_size, self.volume_sectors, &self.vmk)?;
        let rs = replica_sectors(boot.metadata_size, sector_size);
        let lbas = metadata_sector_lbas(
            self.volume_sectors,
            rs,
            boot.header_replica_count as u32,
            boot.footer_replica_count as u32,
        );

        let mut best: Option<JvckMetadata> = None;
        for lba in lbas {
            if let Ok(meta) = read_metadata_at(&self.io, sector_size, lba, &self.vmk) {
                let replace = match &best {
                    Some(b) => meta.encrypted_offset > b.encrypted_offset,
                    None => true,
                };
                if replace {
                    best = Some(meta);
                }
            }
        }
        best.ok_or(VckError::NotFound("no valid JVCK metadata replica"))
    }

    fn write_all_replicas(&self, meta: &JvckMetadata) -> VckResult<()> {
        let mut block = [0u8; METADATA_BLOCK_SIZE];
        meta.encode(&self.vmk, &mut block)?;
        let rs = replica_sectors(self.options.metadata_size, self.geometry.sector_size);
        for lba in metadata_sector_lbas(
            self.volume_sectors,
            rs,
            self.options.use_header,
            self.options.use_footer,
        ) {
            write_block(&self.io, self.geometry.sector_size, lba, &block)?;
        }
        Ok(())
    }

    pub fn offset_sector(&self) -> u64 {
        self.geometry.offset_sector
    }

    pub fn data_sector_count(&self) -> u64 {
        self.geometry.data_sectors
    }

    pub fn sector_size(&self) -> u32 {
        self.geometry.sector_size
    }

    pub fn footer_replica_count(&self) -> u32 {
        self.options.use_footer
    }

    pub fn metadata_size(&self) -> u32 {
        self.options.metadata_size
    }
}

impl<S: SectorIo> EncryptedOffsetStore for JvckMetadataStore<S>
where
    S: Send + Sync + 'static,
{
    fn load(&self) -> VckResult<EncryptedOffset> {
        let meta = self.load_metadata()?;
        Ok(EncryptedOffset {
            sector: meta.encrypted_offset,
            total_sectors: self.geometry.data_sectors,
        })
    }

    fn store(&self, offset: &EncryptedOffset) -> VckResult<()> {
        let mut meta = self.template.clone();
        meta.encrypted_offset = offset.sector;
        self.write_all_replicas(&meta)
    }

    fn flush(&self) -> VckResult<()> {
        // Writes go straight through the synchronous SectorIo; nothing to flush.
        Ok(())
    }
}

// --- UEFI Block IO backed SectorIo + convenience constructor ---
//
// Provided here (under the `uefi` feature) because the loader only needs plain
// sector reads of the target volume to recover FVEK/encrypted_offset; the
// Block IO *hooking* engine lives in `lib/loader`.
#[cfg(feature = "uefi")]
pub use uefi_io::{open_volume_footer_uefi, UefiBlockIoVolume};

#[cfg(feature = "uefi")]
mod uefi_io {
    use super::*;
    use crate::types::Guid;

    /// `SectorIo` backed by `EFI_BLOCK_IO_PROTOCOL` for a located volume.
    pub struct UefiBlockIoVolume {
        // TODO(loader): hold the located block-io handle / protocol pointer.
        _private: (),
    }

    impl SectorIo for UefiBlockIoVolume {
        fn sector_size(&self) -> u32 {
            todo!("uefi block media block size")
        }
        fn total_sectors(&self) -> u64 {
            todo!("uefi block media last block + 1")
        }
        fn read_sectors(&self, _lba: u64, _buf: &mut [u8]) -> VckResult<()> {
            todo!("EFI_BLOCK_IO_PROTOCOL.ReadBlocks")
        }
        fn write_sectors(&self, _lba: u64, _buf: &[u8]) -> VckResult<()> {
            todo!("EFI_BLOCK_IO_PROTOCOL.WriteBlocks")
        }
    }

    /// Locate the volume by `partition_guid`, open its Block IO, and build a
    /// store from the footer metadata using `vmk`.
    pub fn open_volume_footer_uefi(
        partition_guid: Guid,
        vmk: &[u8],
    ) -> VckResult<JvckMetadataStore<UefiBlockIoVolume>> {
        // TODO(loader): LocateHandleBuffer(BlockIo) -> match GPT partition GUID
        // -> construct UefiBlockIoVolume -> JvckMetadataStore::open.
        let _ = (partition_guid, vmk);
        todo!("open UEFI volume footer metadata store")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// In-memory `SectorIo` for tests.
    struct MemVolume {
        sector_size: u32,
        data: Mutex<Vec<u8>>,
    }

    impl MemVolume {
        fn new(sector_size: u32, sectors: u64) -> Self {
            Self {
                sector_size,
                data: Mutex::new(alloc::vec![0u8; (sectors * sector_size as u64) as usize]),
            }
        }
    }

    impl SectorIo for MemVolume {
        fn sector_size(&self) -> u32 {
            self.sector_size
        }
        fn total_sectors(&self) -> u64 {
            self.data.lock().unwrap().len() as u64 / self.sector_size as u64
        }
        fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> VckResult<()> {
            let data = self.data.lock().unwrap();
            let start = (lba * self.sector_size as u64) as usize;
            buf.copy_from_slice(&data[start..start + buf.len()]);
            Ok(())
        }
        fn write_sectors(&self, lba: u64, buf: &[u8]) -> VckResult<()> {
            let mut data = self.data.lock().unwrap();
            let start = (lba * self.sector_size as u64) as usize;
            data[start..start + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    const VMK: &[u8] = b"unit-test-volume-master-key";
    const MD_SIZE: u32 = 128 * 1024; // 256 sectors @ 512

    fn footer_only_options() -> JvckMetadataOptions {
        JvckMetadataOptions {
            use_header: 0,
            use_footer: 2,
            metadata_size: MD_SIZE,
        }
    }

    #[test]
    fn create_then_load_geometry() {
        // 1024 sectors: 2 footer replicas (512) + 512 data sectors.
        let io = MemVolume::new(512, 1024);
        let store =
            JvckMetadataStore::create(io, VMK, footer_only_options(), [1; 32], [2; 32], [9; 16])
                .unwrap();
        assert_eq!(store.offset_sector(), 0);
        assert_eq!(store.data_sector_count(), 512);
        assert_eq!(store.footer_replica_count(), 2);

        let meta = store.load_metadata().unwrap();
        assert_eq!(meta.encrypted_offset, 0);
        assert_eq!(meta.fvek_key1, [1; 32]);
        assert_eq!(meta.volume_id, [9; 16]);
    }

    #[test]
    fn header_plus_footer_geometry() {
        // use_header=1, use_footer=2 -> 3*256 = 768 reserved, 1280 volume.
        let io = MemVolume::new(512, 1280);
        let opts = JvckMetadataOptions {
            use_header: 1,
            use_footer: 2,
            metadata_size: MD_SIZE,
        };
        let store = JvckMetadataStore::create(io, VMK, opts, [3; 32], [4; 32], [7; 16]).unwrap();
        assert_eq!(store.offset_sector(), 256);
        assert_eq!(store.data_sector_count(), 512);
    }

    #[test]
    fn store_then_load_offset_roundtrip() {
        let io = MemVolume::new(512, 1024);
        let store =
            JvckMetadataStore::create(io, VMK, footer_only_options(), [1; 32], [2; 32], [9; 16])
                .unwrap();

        store
            .store(&EncryptedOffset {
                sector: 1234,
                total_sectors: 512,
            })
            .unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.sector, 1234);
        assert_eq!(loaded.total_sectors, 512);
    }

    #[test]
    fn reopen_finds_existing_metadata() {
        let io = MemVolume::new(512, 1024);
        let store =
            JvckMetadataStore::create(io, VMK, footer_only_options(), [5; 32], [6; 32], [8; 16])
                .unwrap();
        store
            .store(&EncryptedOffset {
                sector: 777,
                total_sectors: 512,
            })
            .unwrap();
        // Move the backing volume out and reopen via JvckMetadataStore::open.
        let io = store.io;
        let reopened = JvckMetadataStore::open(io, VMK).unwrap();
        assert_eq!(reopened.offset_sector(), 0);
        assert_eq!(reopened.data_sector_count(), 512);
        assert_eq!(reopened.load_metadata().unwrap().encrypted_offset, 777);
    }

    #[test]
    fn recovery_picks_largest_offset() {
        let io = MemVolume::new(512, 1024);
        let store =
            JvckMetadataStore::create(io, VMK, footer_only_options(), [1; 32], [2; 32], [9; 16])
                .unwrap();
        // All replicas at 500.
        store
            .store(&EncryptedOffset {
                sector: 500,
                total_sectors: 512,
            })
            .unwrap();

        // Corrupt the last footer replica (very last sector) to a stale 300.
        let mut stale = store.template.clone();
        stale.encrypted_offset = 300;
        let mut block = [0u8; METADATA_BLOCK_SIZE];
        stale.encode(VMK, &mut block).unwrap();
        write_block(&store.io, 512, store.volume_sectors - 1, &block).unwrap();

        // load_metadata must still report 500 (the other valid replica).
        assert_eq!(store.load_metadata().unwrap().encrypted_offset, 500);
    }

    #[test]
    fn open_empty_volume_fails() {
        let io = MemVolume::new(512, 1024);
        assert!(matches!(
            JvckMetadataStore::open(io, VMK),
            Err(VckError::NotFound(_))
        ));
    }
}
