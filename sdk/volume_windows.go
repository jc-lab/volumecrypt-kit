//go:build windows

package vck

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type getLengthInformation struct {
	Length int64
}

type diskGeometry struct {
	Cylinders         int64
	MediaType         uint32
	TracksPerCylinder uint32
	SectorsPerTrack   uint32
	BytesPerSector    uint32
}

type diskGeometryEx struct {
	Geometry diskGeometry
	DiskSize int64
}

type shrinkVolumeInformation struct {
	ShrinkRequestType  uint32
	Flags              uint64
	NewNumberOfSectors int64
}

type ntfsVolumeDataBuffer struct {
	VolumeSerialNumber          int64
	NumberSectors               int64
	TotalClusters               int64
	FreeClusters                int64
	TotalReserved               int64
	BytesPerSector              uint32
	BytesPerCluster             uint32
	BytesPerFileRecordSegment   uint32
	ClustersPerFileRecordSegment uint32
	MftValidDataLength          int64
	MftStartLcn                 int64
	Mft2StartLcn                int64
	MftZoneStart                int64
	MftZoneEnd                  int64
}

type startingLcnInputBuffer struct {
	StartingLcn int64
}

type volumeBitmapBuffer struct {
	StartingLcn int64
	BitmapSize  int64
}

type startingVcnInputBuffer struct {
	StartingVcn int64
}

type retrievalPointersBuffer struct {
	ExtentCount uint32
	_           uint32
	StartingVcn int64
}

type retrievalExtent struct {
	NextVcn int64
	Lcn     int64
}

type moveFileData struct {
	FileHandle   windows.Handle
	StartingVcn  int64
	StartingLcn  int64
	ClusterCount uint32
	_            uint32
}

const (
	ioctlDiskGetLengthInfo      = 0x0007405c
	ioctlDiskGetDriveGeometryEx = 0x000700a0
	fsctlShrinkVolume           = 0x000901b0
	fsctlGetNtfsVolumeData      = 0x00090064
	fsctlGetVolumeBitmap        = 0x0009006f
	fsctlGetRetrievalPointers   = 0x00090073
	fsctlMoveFile               = 0x00090074
	// CTL_CODE(FILE_DEVICE_FILE_SYSTEM=9, fn, METHOD_BUFFERED=0, FILE_ANY_ACCESS)
	fsctlLockVolume     = 0x00090018 // fn=6
	fsctlUnlockVolume   = 0x0009001c // fn=7
	fsctlDismountVolume = 0x00090020 // fn=8
	shrinkPrepare       = 1
	shrinkCommit        = 2
	shrinkAbort         = 3
	bitmapBufferSize    = 1 << 16
	retrievalBufferSize = 1 << 12
)

// ShrinkVolumeTail reserves raw sectors at the end of a volume using
// FSCTL_SHRINK_VOLUME. The caller supplies the number of bytes that must be
// freed at the tail.
func ShrinkVolumeTail(volumePath string, reservedTailBytes uint64) error {
	if reservedTailBytes == 0 {
		return fmt.Errorf("reserved tail size must be greater than zero")
	}

	handle, err := openVolumeHandle(volumePath, windows.GENERIC_READ|windows.GENERIC_WRITE)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	volumeLength, bytesPerSector, err := readVolumeLengthAndSectorSizeFromHandle(handle)
	if err != nil {
		return err
	}
	ntfsData, err := readNTFSVolumeData(handle)
	if err != nil {
		return err
	}

	targetBytes := volumeLength - int64(reservedTailBytes)
	if targetBytes <= 0 {
		return fmt.Errorf("target volume size is invalid")
	}
	targetSectors := targetBytes / int64(bytesPerSector)
	if targetSectors <= 0 {
		return fmt.Errorf("target sector count is invalid")
	}

	var bytesReturned uint32
	prepare := shrinkVolumeInformation{
		ShrinkRequestType:  shrinkPrepare,
		Flags:              0,
		NewNumberOfSectors: targetSectors,
	}
	if err := windows.DeviceIoControl(
		handle,
		fsctlShrinkVolume,
		(*byte)(unsafe.Pointer(&prepare)),
		uint32(unsafe.Sizeof(prepare)),
		nil,
		0,
		&bytesReturned,
		nil,
	); err != nil {
		return fmt.Errorf("FSCTL_SHRINK_VOLUME prepare failed: %w", err)
	}

	commit := shrinkVolumeInformation{
		ShrinkRequestType:  shrinkCommit,
		Flags:              0,
		NewNumberOfSectors: 0,
	}
	for {
		if err := windows.DeviceIoControl(
			handle,
			fsctlShrinkVolume,
			(*byte)(unsafe.Pointer(&commit)),
			uint32(unsafe.Sizeof(commit)),
			nil,
			0,
			&bytesReturned,
			nil,
		); err != nil {
			if err == windows.ERROR_ACCESS_DENIED {
				thresholdClusters := int64((reservedTailBytes + uint64(ntfsData.BytesPerCluster) - 1) / uint64(ntfsData.BytesPerCluster))
				thresholdLCN := ntfsData.TotalClusters - thresholdClusters
				moved, moveErr := moveTailClustersBeforeThreshold(handle, volumePath, thresholdLCN)
				if moveErr != nil {
					return fmt.Errorf("FSCTL_MOVE_FILE relocation failed: %w", moveErr)
				}
				if moved {
					continue
				}
			}

			abort := shrinkVolumeInformation{
				ShrinkRequestType:  shrinkAbort,
				Flags:              0,
				NewNumberOfSectors: 0,
			}
			_ = windows.DeviceIoControl(
				handle,
				fsctlShrinkVolume,
				(*byte)(unsafe.Pointer(&abort)),
				uint32(unsafe.Sizeof(abort)),
				nil,
				0,
				&bytesReturned,
				nil,
			)
			return fmt.Errorf("FSCTL_SHRINK_VOLUME commit failed: %w", err)
		}
		break
	}

	return nil
}

func readNTFSVolumeData(handle windows.Handle) (*ntfsVolumeDataBuffer, error) {
	var bytesReturned uint32
	var data ntfsVolumeDataBuffer
	if err := windows.DeviceIoControl(
		handle,
		fsctlGetNtfsVolumeData,
		nil,
		0,
		(*byte)(unsafe.Pointer(&data)),
		uint32(unsafe.Sizeof(data)),
		&bytesReturned,
		nil,
	); err != nil {
		return nil, fmt.Errorf("failed to read NTFS volume data: %w", err)
	}
	return &data, nil
}

func moveTailClustersBeforeThreshold(volumeHandle windows.Handle, volumePath string, thresholdLCN int64) (bool, error) {
	rootPath, err := volumeRootFromPath(volumePath)
	if err != nil {
		return false, err
	}

	scanner := newFreeClusterScanner(volumeHandle, thresholdLCN)
	movedAny := false

	walkErr := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}

		if strings.EqualFold(path, rootPath) {
			return nil
		}

		fileHandle, err := openMovablePath(path, info.IsDir())
		if err != nil {
			return nil
		}
		defer windows.CloseHandle(fileHandle)

		for {
			moved, err := moveSingleTailCluster(volumeHandle, fileHandle, thresholdLCN, scanner)
			if err != nil {
				return nil
			}
			if !moved {
				break
			}
			movedAny = true
		}
		return nil
	})
	if walkErr != nil {
		return false, walkErr
	}
	return movedAny, nil
}

func moveSingleTailCluster(volumeHandle windows.Handle, fileHandle windows.Handle, thresholdLCN int64, scanner *freeClusterScanner) (bool, error) {
	startingVCN := int64(0)

	for {
		extents, moreData, err := getRetrievalPointers(fileHandle, startingVCN)
		if err != nil {
			return false, err
		}

		currentVCN := startingVCN
		for _, extent := range extents {
			extentLength := extent.NextVcn - currentVCN
			if extent.Lcn >= 0 && extentLength > 0 && extent.Lcn+extentLength > thresholdLCN {
				clusterOffset := maxInt64(0, thresholdLCN-extent.Lcn)
				vcnToMove := currentVCN + clusterOffset
				for attempts := 0; attempts < 1024; attempts++ {
					targetLCN, ok, err := scanner.Next()
					if err != nil {
						return false, err
					}
					if !ok {
						return false, fmt.Errorf("no free cluster found below shrink threshold")
					}
					if err := moveOneCluster(volumeHandle, fileHandle, vcnToMove, targetLCN); err == nil {
						return true, nil
					}
				}
				return false, fmt.Errorf("failed to relocate a tail cluster after repeated attempts")
			}
			currentVCN = extent.NextVcn
		}

		if !moreData {
			return false, nil
		}
		startingVCN = currentVCN
	}
}

func moveOneCluster(volumeHandle windows.Handle, fileHandle windows.Handle, startingVCN int64, targetLCN int64) error {
	var bytesReturned uint32
	request := moveFileData{
		FileHandle:   fileHandle,
		StartingVcn:  startingVCN,
		StartingLcn:  targetLCN,
		ClusterCount: 1,
	}

	return windows.DeviceIoControl(
		volumeHandle,
		fsctlMoveFile,
		(*byte)(unsafe.Pointer(&request)),
		uint32(unsafe.Sizeof(request)),
		nil,
		0,
		&bytesReturned,
		nil,
	)
}

func getRetrievalPointers(fileHandle windows.Handle, startingVCN int64) ([]retrievalExtent, bool, error) {
	in := startingVcnInputBuffer{StartingVcn: startingVCN}
	out := make([]byte, retrievalBufferSize)
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		fileHandle,
		fsctlGetRetrievalPointers,
		(*byte)(unsafe.Pointer(&in)),
		uint32(unsafe.Sizeof(in)),
		&out[0],
		uint32(len(out)),
		&bytesReturned,
		nil,
	)
	moreData := err == windows.ERROR_MORE_DATA
	if err != nil && !moreData {
		return nil, false, err
	}
	if bytesReturned < uint32(unsafe.Sizeof(retrievalPointersBuffer{})) {
		return nil, moreData, nil
	}

	header := (*retrievalPointersBuffer)(unsafe.Pointer(&out[0]))
	extents := make([]retrievalExtent, 0, header.ExtentCount)
	base := uintptr(unsafe.Pointer(&out[0])) + unsafe.Sizeof(retrievalPointersBuffer{})
	for i := uint32(0); i < header.ExtentCount; i++ {
		extent := *(*retrievalExtent)(unsafe.Pointer(base + uintptr(i)*unsafe.Sizeof(retrievalExtent{})))
		extents = append(extents, extent)
	}
	return extents, moreData, nil
}

type freeClusterScanner struct {
	volumeHandle windows.Handle
	thresholdLCN int64
	nextLCN      int64
	chunkStart   int64
	chunkSize    int64
	bitmap       []byte
}

func newFreeClusterScanner(volumeHandle windows.Handle, thresholdLCN int64) *freeClusterScanner {
	return &freeClusterScanner{
		volumeHandle: volumeHandle,
		thresholdLCN: thresholdLCN,
		nextLCN:      0,
		chunkStart:   -1,
	}
}

func (s *freeClusterScanner) Next() (int64, bool, error) {
	for s.nextLCN < s.thresholdLCN {
		if s.chunkStart < 0 || s.nextLCN < s.chunkStart || s.nextLCN >= s.chunkStart+s.chunkSize {
			if err := s.loadBitmap(s.nextLCN); err != nil {
				return 0, false, err
			}
			if s.chunkSize == 0 {
				return 0, false, nil
			}
		}

		offset := s.nextLCN - s.chunkStart
		if offset >= 0 && offset < s.chunkSize {
			if !bitIsSet(s.bitmap, offset) {
				lcn := s.nextLCN
				s.nextLCN++
				return lcn, true, nil
			}
		}
		s.nextLCN++
	}
	return 0, false, nil
}

func (s *freeClusterScanner) loadBitmap(startLCN int64) error {
	in := startingLcnInputBuffer{StartingLcn: startLCN}
	out := make([]byte, bitmapBufferSize)
	var bytesReturned uint32

	err := windows.DeviceIoControl(
		s.volumeHandle,
		fsctlGetVolumeBitmap,
		(*byte)(unsafe.Pointer(&in)),
		uint32(unsafe.Sizeof(in)),
		&out[0],
		uint32(len(out)),
		&bytesReturned,
		nil,
	)
	if err != nil && err != windows.ERROR_MORE_DATA {
		return err
	}
	if bytesReturned < uint32(unsafe.Sizeof(volumeBitmapBuffer{})) {
		s.chunkStart = startLCN
		s.chunkSize = 0
		s.bitmap = nil
		return nil
	}

	header := (*volumeBitmapBuffer)(unsafe.Pointer(&out[0]))
	bitmapOffset := int(unsafe.Sizeof(volumeBitmapBuffer{}))
	bitmapBytes := int(bytesReturned) - bitmapOffset
	if bitmapBytes < 0 {
		bitmapBytes = 0
	}
	s.chunkStart = header.StartingLcn
	s.chunkSize = minInt64(int64(bitmapBytes)*8, header.BitmapSize)
	s.bitmap = out[bitmapOffset : bitmapOffset+bitmapBytes]
	return nil
}

func bitIsSet(bitmap []byte, index int64) bool {
	byteIndex := index / 8
	bitIndex := index % 8
	if byteIndex < 0 || int(byteIndex) >= len(bitmap) {
		return true
	}
	return (bitmap[byteIndex] & (1 << bitIndex)) != 0
}

func openMovablePath(path string, isDir bool) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	flags := uint32(0)
	if isDir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}

	return windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
}

// --- Volume path normalization ------------------------------------------------
//
// Accepted input formats for any `--volume` argument:
//   - drive letter:        "D:", "D:\", "\\.\D:", "\\?\D:"
//   - volume GUID path:    "\\?\Volume{GUID}", "\\?\Volume{GUID}\", "\\.\Volume{GUID}"
//
// Canonical form (for display + as the registry key sent to the driver) is the
// volume GUID path "\\?\Volume{GUID}\". A device-open form (CreateFile-able raw
// volume handle, no trailing backslash) is derived for I/O.

var (
	modkernel32                           = windows.NewLazySystemDLL("kernel32.dll")
	procGetVolumeNameForVolumeMountPointW = modkernel32.NewProc("GetVolumeNameForVolumeMountPointW")
)

// isVolumeGUIDPath reports whether s is a "\\?\Volume{...}" / "\\.\Volume{...}" path.
func isVolumeGUIDPath(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, `\\?\Volume{`) || strings.HasPrefix(t, `\\.\Volume{`)
}

// volumeGUIDName extracts the "Volume{GUID}" DOS device name from a GUID path.
func volumeGUIDName(s string) string {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(t, `\\?\`)
	t = strings.TrimPrefix(t, `\\.\`)
	return strings.TrimSuffix(t, `\`)
}

// extractDriveLetter returns "D:" for any drive-letter form, or "" otherwise.
func extractDriveLetter(s string) string {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, `\\.\`) || strings.HasPrefix(t, `\\?\`) {
		t = t[4:]
	}
	if len(t) >= 2 && t[1] == ':' {
		c := t[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return strings.ToUpper(t[:1]) + ":"
		}
	}
	return ""
}

// getVolumeNameForMountPoint wraps GetVolumeNameForVolumeMountPointW. `mountPoint`
// must end with a backslash (e.g. "D:\"). Returns "\\?\Volume{GUID}\".
func getVolumeNameForMountPoint(mountPoint string) (string, error) {
	mp, err := windows.UTF16PtrFromString(mountPoint)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, 64) // "\\?\Volume{...}\" needs ~50 chars
	r, _, e := procGetVolumeNameForVolumeMountPointW.Call(
		uintptr(unsafe.Pointer(mp)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r == 0 {
		return "", fmt.Errorf("GetVolumeNameForVolumeMountPoint(%s): %w", mountPoint, e)
	}
	return windows.UTF16ToString(buf), nil
}

// CanonicalVolumePath resolves any accepted volume input to its canonical volume
// GUID path "\\?\Volume{GUID}\". Used for display and as the driver registry key.
func CanonicalVolumePath(input string) (string, error) {
	if isVolumeGUIDPath(input) {
		return `\\?\` + volumeGUIDName(input) + `\`, nil
	}
	letter := extractDriveLetter(input)
	if letter == "" {
		return "", fmt.Errorf("unsupported volume path: %q", input)
	}
	return getVolumeNameForMountPoint(letter + `\`)
}

// volumeDeviceOpenPath returns a CreateFile-openable raw-volume device path
// (no trailing backslash) for any accepted volume input.
func volumeDeviceOpenPath(input string) (string, error) {
	if isVolumeGUIDPath(input) {
		return `\\?\` + volumeGUIDName(input), nil
	}
	if letter := extractDriveLetter(input); letter != "" {
		return `\\.\` + letter, nil
	}
	return "", fmt.Errorf("unsupported volume path: %q", input)
}

func volumeRootFromPath(volumePath string) (string, error) {
	if isVolumeGUIDPath(volumePath) {
		return `\\?\` + volumeGUIDName(volumePath) + `\`, nil
	}
	if letter := extractDriveLetter(volumePath); letter != "" {
		return letter + `\`, nil
	}
	return "", fmt.Errorf("unsupported volume path format: %s", volumePath)
}

func minInt64(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a int64, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// VolumeNTDevicePath returns the NT kernel device path for a Win32 volume path
// (e.g. `\\.\D:` → `\Device\HarddiskVolume3`). The NT path works with
// ZwCreateFile regardless of whether a filesystem is currently mounted.
func VolumeNTDevicePath(volumePath string) (string, error) {
	// QueryDosDevice resolves a DOS device name to its NT target. The DOS name
	// is "D:" for drive letters and "Volume{GUID}" for volume GUID paths.
	var dosName string
	if isVolumeGUIDPath(volumePath) {
		dosName = volumeGUIDName(volumePath)
	} else if letter := extractDriveLetter(volumePath); letter != "" {
		dosName = letter
	} else {
		return "", fmt.Errorf("cannot resolve NT device path from %q", volumePath)
	}

	name16, err := windows.UTF16PtrFromString(dosName)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, 256)
	n, err := windows.QueryDosDevice(name16, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", fmt.Errorf("QueryDosDevice(%s) failed: %w", dosName, err)
	}
	if n == 0 {
		return "", fmt.Errorf("QueryDosDevice(%s) returned empty result", dosName)
	}
	// Result is a NUL-terminated string (possibly multi-string); take the first.
	return windows.UTF16ToString(buf[:n]), nil
}

// LockDismountVolume locks the volume for exclusive access and dismounts the
// file system (e.g. NTFS), causing it to detach from the device stack. The
// caller MUST call UnlockVolume with the returned handle to re-allow mounting.
//
// This is required before the kernel driver attaches its filter so that the
// filter is inserted below the file system rather than above it. After the
// IOCTL_JVCK_ATTACH call returns, call UnlockVolume so Windows re-mounts the
// file system above the newly inserted filter.
func LockDismountVolume(volumePath string) (windows.Handle, error) {
	// FSCTL_LOCK_VOLUME requires that no other processes have open handles to
	// files on the volume. Open with FILE_SHARE_READ|FILE_SHARE_WRITE to avoid
	// blocking other opens, and retry up to 5 times to handle brief holds.
	handle, err := openVolumeHandle(volumePath, windows.GENERIC_READ|windows.GENERIC_WRITE)
	if err != nil {
		return windows.InvalidHandle, err
	}
	var bytesReturned uint32
	var lockErr error
	for i := 0; i < 5; i++ {
		lockErr = windows.DeviceIoControl(handle, fsctlLockVolume, nil, 0, nil, 0, &bytesReturned, nil)
		if lockErr == nil {
			break
		}
	}
	if lockErr != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, fmt.Errorf("FSCTL_LOCK_VOLUME failed: %w", lockErr)
	}
	if err := windows.DeviceIoControl(handle, fsctlDismountVolume, nil, 0, nil, 0, &bytesReturned, nil); err != nil {
		// Non-fatal: unlock and close so the volume is usable.
		_ = windows.DeviceIoControl(handle, fsctlUnlockVolume, nil, 0, nil, 0, &bytesReturned, nil)
		windows.CloseHandle(handle)
		return windows.InvalidHandle, fmt.Errorf("FSCTL_DISMOUNT_VOLUME failed: %w", err)
	}
	return handle, nil
}

// UnlockVolume releases the exclusive lock held by LockDismountVolume, allowing
// the OS to re-mount the file system above the driver's filter. Closes the
// handle on return.
func UnlockVolume(handle windows.Handle) error {
	var bytesReturned uint32
	err := windows.DeviceIoControl(handle, fsctlUnlockVolume, nil, 0, nil, 0, &bytesReturned, nil)
	windows.CloseHandle(handle)
	if err != nil {
		return fmt.Errorf("FSCTL_UNLOCK_VOLUME failed: %w", err)
	}
	return nil
}

// VolumeLengthAndSectorSize returns the current raw volume length and bytes per
// sector for a Windows volume path such as `\\.\C:`.
func VolumeLengthAndSectorSize(volumePath string) (int64, uint32, error) {
	return readVolumeLengthAndSectorSize(volumePath)
}

func openVolumeHandle(volumePath string, access uint32) (windows.Handle, error) {
	if access == 0 {
		access = windows.GENERIC_READ
	}

	// Normalize any accepted format (D:, \\.\D:, \\?\Volume{GUID}) to a raw
	// device path CreateFile can open.
	devicePath, err := volumeDeviceOpenPath(volumePath)
	if err != nil {
		return 0, err
	}

	pathPtr, err := windows.UTF16PtrFromString(devicePath)
	if err != nil {
		return 0, fmt.Errorf("failed to encode volume path: %w", err)
	}

	handle, err := windows.CreateFile(
		pathPtr,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to open %s: %w", volumePath, err)
	}
	return handle, nil
}

func readVolumeLengthAndSectorSize(volumePath string) (int64, uint32, error) {
	handle, err := openVolumeHandle(volumePath, 0)
	if err != nil {
		return 0, 0, err
	}
	defer windows.CloseHandle(handle)

	return readVolumeLengthAndSectorSizeFromHandle(handle)
}

func readVolumeLengthAndSectorSizeFromHandle(handle windows.Handle) (int64, uint32, error) {
	var bytesReturned uint32

	var lengthInfo getLengthInformation
	if err := windows.DeviceIoControl(
		handle,
		ioctlDiskGetLengthInfo,
		nil,
		0,
		(*byte)(unsafe.Pointer(&lengthInfo)),
		uint32(unsafe.Sizeof(lengthInfo)),
		&bytesReturned,
		nil,
	); err != nil {
		return 0, 0, fmt.Errorf("failed to read volume length: %w", err)
	}

	var geometry diskGeometryEx
	if err := windows.DeviceIoControl(
		handle,
		ioctlDiskGetDriveGeometryEx,
		nil,
		0,
		(*byte)(unsafe.Pointer(&geometry)),
		uint32(unsafe.Sizeof(geometry)),
		&bytesReturned,
		nil,
	); err != nil {
		return 0, 0, fmt.Errorf("failed to read drive geometry: %w", err)
	}
	if geometry.Geometry.BytesPerSector == 0 {
		return 0, 0, fmt.Errorf("drive reported zero bytes per sector")
	}

	return lengthInfo.Length, geometry.Geometry.BytesPerSector, nil
}
