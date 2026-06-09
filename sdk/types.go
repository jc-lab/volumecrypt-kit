package vck

// EncryptionState is the encryption progress state of a volume as reported by
// the driver.
type EncryptionState int

const (
	StateIdle       EncryptionState = 0 // Idle (includes fully encrypted)
	StateEncrypting EncryptionState = 1 // Incremental encryption in progress
	StateDecrypting EncryptionState = 2 // Incremental decryption in progress
	StatePaused     EncryptionState = 3 // Paused
)

// VolumeStatus is the IOCTL_VCK_GET_STATUS response structure.
type VolumeStatus struct {
	VolumePath      string          `msgpack:"volume_path"`
	State           EncryptionState `msgpack:"state"`
	EncryptedSector uint64          `msgpack:"encrypted_sector"`
	TotalSectors    uint64          `msgpack:"total_sectors"`
	SectorSize      uint32          `msgpack:"sector_size"`
	IsAttached      bool            `msgpack:"is_attached"`
	// FilterBelowFsd is true when the driver's filter is correctly placed BELOW
	// the filesystem (via AddDevice at boot). false means the driver needs a
	// reboot for the filter to be in the correct position.
	FilterBelowFsd bool `msgpack:"filter_below_fsd"`
}

// ProgressPercent returns the encryption progress as a percentage.
func (s *VolumeStatus) ProgressPercent() float64 {
	if s.TotalSectors == 0 {
		return 0
	}
	return float64(s.EncryptedSector) / float64(s.TotalSectors) * 100
}

// IsFullyEncrypted reports whether the entire data region has been encrypted.
func (s *VolumeStatus) IsFullyEncrypted() bool {
	return s.EncryptedSector >= s.TotalSectors
}

// ─── Data Volume: Attach / Detach ────────────────────────────────────────────

// ─── Data Volume: Prepare / Attach (two-phase) ───────────────────────────────

// JvckVolumePrepareRequest is the IOCTL_JVCK_PREPARE request (phase 1).
//
// The driver attaches the volume filter below the filesystem and activates size
// hiding so NTFS remounts seeing only the data region. NTFS will NOT write its
// VBR backup into the footer metadata region. After this call returns, the app
// calls EnsureJvckMetadata to write the JVCK footer, then calls Attach.
type JvckVolumePrepareRequest struct {
	VolumePath   string `msgpack:"volume_path"`
	NTDevicePath string `msgpack:"nt_device_path,omitempty"`
	UseHeader    uint32 `msgpack:"use_header"`
	UseFooter    uint32 `msgpack:"use_footer"`
	MetadataSize uint32 `msgpack:"metadata_size"`
	// VMK used by the driver to recover the FVEK from MetadataBlock.
	// Required when MetadataBlock is non-empty; the driver encrypts sector 0
	// in-kernel while the volume is locked+dismounted (bypasses PartMgr).
	VMK []byte `msgpack:"vmk"`
	// Pre-encoded 512-byte JVCK Metadata block (with encrypted_offset=1 so the
	// sweep starts from sector 1 after sector 0 is pre-encrypted). The driver
	// writes this to every replica LBA while the volume lock is held.
	// Empty means re-attach (skip write).
	MetadataBlock []byte `msgpack:"metadata_block"`
}

// JvckVolumePrepareResponse is the IOCTL_JVCK_PREPARE response.
type JvckVolumePrepareResponse struct {
	OffsetSector     uint64 `msgpack:"offset_sector"`
	DataSectors      uint64 `msgpack:"data_sectors"`
	SectorSize       uint32 `msgpack:"sector_size"`
	RawPartitionPath string `msgpack:"raw_partition_path,omitempty"`
	RawDiskPath      string `msgpack:"raw_disk_path,omitempty"`
	PartitionStartLba uint64 `msgpack:"partition_start_lba,omitempty"`
	// true when PREPARE completed full attach (VMK provided); app needs no separate Attach call.
	FullyAttached bool `msgpack:"fully_attached,omitempty"`
}

// JvckVolumeAttachRequest is the IOCTL_JVCK_ATTACH request structure.
// It registers a Data Volume with the driver using the default JVCK format and
// activates the encryption layer. offset_sector/total_sectors/encrypted_sector
// are restored from the JVCK metadata or computed from
// use_header/use_footer/metadata_size, so they are not part of the request.
//
// The driver only ever OPENS existing metadata; first-time creation (FVEK +
// volume-id generation and the footer write) is done by the SDK via
// EnsureJvckMetadata before attach, so no key material is sent in this request.
type JvckVolumeAttachRequest struct {
	// Required. Volume path. Either a volume GUID path (\\?\Volume{...}\) or a
	// drive path (C:\, \\.\D:) is accepted.
	VolumePath string `msgpack:"volume_path"`
	// Required. VMK used to open the JVCK metadata.
	VMK []byte `msgpack:"vmk"`
	// Advisory layout (authoritatively recovered from the on-disk header). Only
	// new partitions may use UseHeader >= 1; existing partitions use 0.
	UseHeader    uint32 `msgpack:"use_header"`
	UseFooter    uint32 `msgpack:"use_footer"`
	MetadataSize uint32 `msgpack:"metadata_size"`
	// NT kernel device path (e.g. `\Device\HarddiskVolume3`). When supplied,
	// the driver uses this path instead of the Win32 VolumePath for ZwCreateFile,
	// allowing access even when the volume's filesystem is dismounted.
	// Obtain via VolumeNTDevicePath before calling Attach.
	NTDevicePath string `msgpack:"nt_device_path,omitempty"`
	// Raw partition path from PREPARE (e.g. `\Device\Harddisk0\Partition1`).
	RawPartitionPath string `msgpack:"raw_partition_path,omitempty"`
	// Raw disk path from PREPARE (e.g. `\Device\Harddisk0\DR0`).
	RawDiskPath string `msgpack:"raw_disk_path,omitempty"`
	// Partition start LBA on the physical disk (used with RawDiskPath).
	PartitionStartLba uint64 `msgpack:"partition_start_lba,omitempty"`
}

// JvckVolumeAttachResponse is the IOCTL_JVCK_ATTACH response structure.
type JvckVolumeAttachResponse struct {
	OffsetSector uint64 `msgpack:"offset_sector"`
	TotalSectors uint64 `msgpack:"total_sectors"` // Number of sectors in the actual encryption target region
	SectorSize   uint32 `msgpack:"sector_size"`
}

// VolumeDetachRequest is the IOCTL_VCK_DETACH request structure.
// It releases the encryption layer of an attached Data Volume.
type VolumeDetachRequest struct {
	VolumePath string `msgpack:"volume_path"`
}

// ─── Encryption progress control ─────────────────────────────────────────────

// volumeRequest is the common request structure that carries only volume_path.
// It is used by the GetStatus / Pause / GetProgress IOCTLs. (StartEncrypt and
// StartDecrypt keep their own identically-shaped EncryptRequest/DecryptRequest
// types for clarity of intent.)
type volumeRequest struct {
	VolumePath string `msgpack:"volume_path"`
}

// EncryptRequest is the IOCTL_VCK_START_ENCRYPT request structure.
// Keys are already set at Attach time, so they are not included.
// Both OS Volume and Data Volume use it identically.
type EncryptRequest struct {
	VolumePath string `msgpack:"volume_path"`
}

// DecryptRequest is the IOCTL_VCK_START_DECRYPT request structure.
type DecryptRequest struct {
	VolumePath string `msgpack:"volume_path"`
}

// ProgressEvent is the current progress received as the IOCTL_VCK_GET_PROGRESS
// response.
type ProgressEvent struct {
	EncryptedSector uint64          `msgpack:"encrypted_sector"`
	TotalSectors    uint64          `msgpack:"total_sectors"`
	State           EncryptionState `msgpack:"state"`
	ErrorMessage    string          `msgpack:"error,omitempty"`
}

// ProgressPercent returns the encryption progress as a percentage.
func (e *ProgressEvent) ProgressPercent() float64 {
	if e.TotalSectors == 0 {
		return 0
	}
	return float64(e.EncryptedSector) / float64(e.TotalSectors) * 100
}
