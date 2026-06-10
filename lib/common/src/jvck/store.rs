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

use zeroize::Zeroizing;

use crate::{
    jvck::{
        metadata::{self, JvckHeader, JvckSecrets, METADATA_BLOCK_SIZE},
        options::JvckMetadataOptions,
    },
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
    vmk: Zeroizing<Vec<u8>>,
    geometry: Geometry,
    volume_sectors: u64,
    /// Immutable plaintext template (counts, sizes, volume id). Re-encoded with
    /// `secrets` + the live `encrypted_offset` on every metadata write.
    header: JvckHeader,
    /// FVEK material, kept (zeroize-on-drop) so `store()` can re-encode the
    /// EncryptedMetadata blob when `encrypted_offset` advances.
    secrets: JvckSecrets,
}

/// Sectors-per-replica for the given layout.
///
/// The 512-byte Metadata block always occupies exactly one sector, and the
/// vendor-specific area is `floor((metadata_size - sector_size) / sector_size)`
/// sectors. The total is therefore `floor(metadata_size / sector_size)`: when
/// `metadata_size` is not a multiple of `sector_size` the remainder is dropped
/// so a replica region never exceeds `metadata_size`.
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
    // `metadata_size` need not be a multiple of `sector_size`: the replica region
    // is floored to whole sectors (`floor(metadata_size / sector_size)`), so it
    // never exceeds `metadata_size`. It must still hold at least the one Metadata
    // sector.
    let rs = replica_sectors(options.metadata_size, sector_size);
    if rs == 0 {
        return Err(VckError::ValidationFailed(
            "metadata_size smaller than one sector",
        ));
    }
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

impl<S: SectorIo> JvckMetadataStore<S> {
    /// Open an existing JVCK volume.
    ///
    /// Locates a CRC-valid replica (last sector first — always a footer Metadata
    /// block — then sector 0 for header-only layouts), parses its plaintext
    /// header for the layout, and decrypts the EncryptedMetadata blob ONCE with
    /// `vmk` to authenticate and recover the FVEK. A CRC-valid block that fails
    /// to authenticate propagates the auth error (so a wrong VMK never falls
    /// through to "blank volume" and overwrites a real one); a volume with no
    /// JVCK signature anywhere returns `NotFound`.
    pub fn open(io: S, vmk: &[u8]) -> VckResult<Self> {
        let sector_size = io.sector_size();
        if (sector_size as usize) < METADATA_BLOCK_SIZE {
            return Err(VckError::Unsupported("sector size smaller than 512"));
        }
        let volume_sectors = io.total_sectors();
        if volume_sectors == 0 {
            return Err(VckError::NotFound("empty volume"));
        }

        for lba in [volume_sectors - 1, 0] {
            let block = read_block(&io, sector_size, lba)?;
            if metadata::verify_crc(&block).is_err() {
                continue;
            }
            // Layout is plaintext; the VMK only gates the encrypted FVEK blob.
            let header = JvckHeader::parse(&block)?;
            let (_offset, secrets) = metadata::decrypt_payload(&block, vmk)?;

            let options = JvckMetadataOptions {
                use_header: header.header_replica_count as u32,
                use_footer: header.footer_replica_count as u32,
                metadata_size: header.metadata_size,
            };
            let geometry = compute_geometry(sector_size, volume_sectors, &options)?;
            return Ok(Self {
                io,
                options,
                vmk: Zeroizing::new(vmk.to_vec()),
                geometry,
                volume_sectors,
                header,
                secrets,
            });
        }
        Err(VckError::NotFound("no JVCK metadata present"))
    }

    /// Initialize a brand new JVCK volume (first-time encryption): lay out the
    /// replicas per `options` and write seed metadata (`encrypted_offset = 0`).
    ///
    /// The kernel driver no longer creates metadata (the user-space SDK does
    /// that over an extended-DASD volume handle); this remains the in-tree
    /// reference encoder used by host tests and tooling.
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

        let header = JvckHeader {
            vendor_id: 0,
            metadata_version: 1,
            vendor_version: 0,
            metadata_size: options.metadata_size,
            sector_size,
            header_replica_count: options.use_header as u8,
            footer_replica_count: options.use_footer as u8,
            volume_id,
        };
        let secrets = JvckSecrets {
            fvek_key1,
            fvek_key2,
        };

        let store = Self {
            io,
            options,
            vmk: Zeroizing::new(vmk.to_vec()),
            geometry,
            volume_sectors,
            header,
            secrets,
        };
        store.write_all_replicas(0)?;
        Ok(store)
    }

    /// Read every replica and return the most up-to-date `encrypted_offset`.
    ///
    /// Uses the cached layout (the on-disk layout is immutable once written, so
    /// re-bootstrapping per call is unnecessary). Recovery policy: among valid
    /// replicas, pick the largest `encrypted_offset`. Only the offset is
    /// recovered; the FVEK decrypted along the way is zeroized immediately.
    pub fn load_offset(&self) -> VckResult<u64> {
        let sector_size = self.geometry.sector_size;
        let rs = replica_sectors(self.options.metadata_size, sector_size);
        let lbas = metadata_sector_lbas(
            self.volume_sectors,
            rs,
            self.options.use_header,
            self.options.use_footer,
        );

        let mut best: Option<u64> = None;
        for lba in lbas {
            let block = match read_block(&self.io, sector_size, lba) {
                Ok(block) => block,
                Err(_) => continue,
            };
            if let Ok(offset) = metadata::read_encrypted_offset(&block, &self.vmk) {
                best = Some(best.map_or(offset, |b| b.max(offset)));
            }
        }
        best.ok_or(VckError::NotFound("no valid JVCK metadata replica"))
    }

    /// FVEK key halves recovered at open/create. Kept zeroize-on-drop in the
    /// store; copied out here only to build the volume cipher.
    pub fn fvek_keys(&self) -> (&[u8; 32], &[u8; 32]) {
        (&self.secrets.fvek_key1, &self.secrets.fvek_key2)
    }

    /// The plaintext Volume ID (HKDF salt) from the metadata header.
    pub fn volume_id(&self) -> [u8; 16] {
        self.header.volume_id
    }

    fn write_all_replicas(&self, encrypted_offset: u64) -> VckResult<()> {
        let mut block = [0u8; METADATA_BLOCK_SIZE];
        self.header
            .encode(&self.secrets, encrypted_offset, &self.vmk, &mut block)?;
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
        Ok(EncryptedOffset {
            sector: self.load_offset()?,
            total_sectors: self.geometry.data_sectors,
        })
    }

    fn store(&self, offset: &EncryptedOffset) -> VckResult<()> {
        self.write_all_replicas(offset.sector)
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
    use crate::types::{guid_from_windows_bytes, Guid};
    use alloc::format;
    use uefi::boot::{self, open_protocol_exclusive, SearchType};
    use uefi::proto::media::block::BlockIO;
    use uefi::proto::media::partition::PartitionInfo;

    /// `SectorIo` backed by `EFI_BLOCK_IO_PROTOCOL` for a located volume.
    ///
    /// Read-only: the loader only needs to read footer metadata replicas to
    /// recover the FVEK / encrypted_offset (the transparent decryption hook
    /// lives in `lib/loader`).
    pub struct UefiBlockIoVolume {
        block_io: uefi::boot::ScopedProtocol<BlockIO>,
        media_id: u32,
        sector_size: u32,
        total_sectors: u64,
    }

    // The loader is single-threaded; `ScopedProtocol` holds raw firmware
    // pointers that are only ever touched from the boot thread. `SectorIo`
    // requires `Send + Sync`, so assert it here.
    unsafe impl Send for UefiBlockIoVolume {}
    unsafe impl Sync for UefiBlockIoVolume {}

    impl SectorIo for UefiBlockIoVolume {
        fn sector_size(&self) -> u32 {
            self.sector_size
        }
        fn total_sectors(&self) -> u64 {
            self.total_sectors
        }
        fn read_sectors(&self, lba: u64, buf: &mut [u8]) -> VckResult<()> {
            self.block_io
                .read_blocks(self.media_id, lba, buf)
                .map_err(|e| VckError::Io(format!("BlockIO.ReadBlocks(lba={lba}) failed: {e:?}")))
        }
        fn write_sectors(&self, _lba: u64, _buf: &[u8]) -> VckResult<()> {
            Err(VckError::Unsupported("loader Block IO volume is read-only"))
        }
    }

    /// Locate the volume by GPT unique `partition_guid`, open its Block IO, and
    /// build a store from the footer metadata using `vmk`.
    pub fn open_volume_footer_uefi(
        partition_guid: Guid,
        vmk: &[u8],
    ) -> VckResult<JvckMetadataStore<UefiBlockIoVolume>> {
        let handles = boot::locate_handle_buffer(SearchType::from_proto::<BlockIO>())
            .map_err(|e| VckError::Io(format!("locate BlockIO handles failed: {e:?}")))?;

        for &handle in handles.iter() {
            // Match by GPT unique partition GUID via the PartitionInfo protocol.
            // PartitionInfo is produced on the partition (logical) handles only.
            let matched = match open_protocol_exclusive::<PartitionInfo>(handle) {
                Ok(pinfo) => match pinfo.gpt_partition_entry() {
                    Some(gpt) => {
                        guid_from_windows_bytes(gpt.unique_partition_guid.to_bytes())
                            == partition_guid
                    }
                    None => false,
                },
                Err(_) => false,
            };
            if !matched {
                continue;
            }

            let block_io = open_protocol_exclusive::<BlockIO>(handle)
                .map_err(|e| VckError::Io(format!("open BlockIO failed: {e:?}")))?;
            let media = block_io.media();
            if !media.is_media_present() {
                return Err(VckError::Io("matched partition has no media present".into()));
            }
            let sector_size = media.block_size();
            let media_id = media.media_id();
            let total_sectors = media.last_block().saturating_add(1);
            let io = UefiBlockIoVolume {
                block_io,
                media_id,
                sector_size,
                total_sectors,
            };
            return JvckMetadataStore::open(io, vmk);
        }

        Err(VckError::NotFound(
            "no Block IO partition matched the target GUID",
        ))
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

        assert_eq!(store.load_offset().unwrap(), 0);
        assert_eq!(store.fvek_keys().0, &[1u8; 32]);
        assert_eq!(store.volume_id(), [9; 16]);
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
        assert_eq!(reopened.load_offset().unwrap(), 777);
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
        let mut block = [0u8; METADATA_BLOCK_SIZE];
        store
            .header
            .encode(&store.secrets, 300, VMK, &mut block)
            .unwrap();
        write_block(&store.io, 512, store.volume_sectors - 1, &block).unwrap();

        // load_offset must still report 500 (the other valid replica).
        assert_eq!(store.load_offset().unwrap(), 500);
    }

    #[test]
    fn open_empty_volume_fails() {
        let io = MemVolume::new(512, 1024);
        assert!(matches!(
            JvckMetadataStore::open(io, VMK),
            Err(VckError::NotFound(_))
        ));
    }

    #[test]
    fn metadata_size_not_multiple_of_sector_is_floored() {
        // 4096-byte sectors with a metadata_size that is NOT a multiple of the
        // sector size: 128 KiB + 100 bytes. The replica region floors to
        // floor(131172 / 4096) = 32 sectors (the trailing 100 bytes are dropped).
        let sector_size = 4096u32;
        let md_size = 128 * 1024 + 100;
        let opts = JvckMetadataOptions {
            use_header: 0,
            use_footer: 2,
            metadata_size: md_size,
        };
        let expected_rs = (md_size / sector_size) as u64; // 32
        assert_eq!(expected_rs, 32);

        // 2 footer replicas (64 sectors) + 64 data sectors.
        let io = MemVolume::new(sector_size, 128);
        let store =
            JvckMetadataStore::create(io, VMK, opts, [1; 32], [2; 32], [9; 16]).unwrap();
        assert_eq!(store.data_sector_count(), 128 - 2 * expected_rs);
        assert_eq!(store.sector_size(), sector_size);

        // The footer Metadata is the last sector and round-trips through reopen.
        store
            .store(&EncryptedOffset {
                sector: 7,
                total_sectors: store.data_sector_count(),
            })
            .unwrap();
        let reopened = JvckMetadataStore::open(store.io, VMK).unwrap();
        assert_eq!(reopened.metadata_size(), md_size);
        assert_eq!(reopened.load_offset().unwrap(), 7);
    }
}
