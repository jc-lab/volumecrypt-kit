// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"crypto/rand"
	"fmt"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

const (
	osVolumeVmkHex        = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	osVolumeOsLoader      = "/EFI/Microsoft/Boot/bootmgfw.os.efi"
	osVolumeDefaultFooter = 2
	osVolumeMetadataSize  = 131072
)

var osVolumePrepareOnly bool
var osVolumeNoWait bool

type osVolumePrepareResult struct {
	VolumePath    string `json:"volume_path"`
	DriveLetter   string `json:"drive_letter"`
	PartitionGUID string `json:"partition_guid"`
	ReservedBytes uint64 `json:"reserved_bytes"`
	TargetSize    uint64 `json:"target_size"`
	OsLoader      string `json:"osloader"`
	VckJSONPath   string `json:"vck_json_path"`
	BootCopyPath  string `json:"boot_copy_path"`
}

type osVolumeConfig struct {
	PartitionGUID string `json:"partition_guid"`
	VMK           string `json:"vmk"`
	OsLoader      string `json:"osloader"`
}

type partitionInformationGPT struct {
	PartitionType windows.GUID
	PartitionID   windows.GUID
	Attributes    uint64
	Name          [36]uint16
}

type partitionInformationEx struct {
	PartitionStyle   uint32
	_                uint32
	StartingOffset   int64
	PartitionLength  int64
	PartitionNumber  uint32
	RewritePartition byte
	_                [3]byte
	Gpt              partitionInformationGPT
}

const (
	partitionStyleGPT             = 1
	ioctlDiskGetPartitionInfoEx   = 0x00070048
	osVolumeFooterReplicaCount    = 2
)

func newOSVolumeEncryptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "prepare the OS volume for first-time encryption and start encryption when attach is ready",
		RunE: func(cmd *cobra.Command, args []string) error {
			prepareResult, err := prepareOSVolume(effectiveOSVolumePath())
			if err != nil {
				return err
			}

			fmt.Printf("Prepared OS volume %s\n", prepareResult.VolumePath)
			fmt.Printf("Partition GUID : %s\n", prepareResult.PartitionGUID)
			fmt.Printf("Reserved bytes : %d\n", prepareResult.ReservedBytes)
			fmt.Printf("Copied loader  : %s\n", prepareResult.BootCopyPath)
			fmt.Printf("Created config : %s\n", prepareResult.VckJSONPath)

			if osVolumePrepareOnly {
				fmt.Println("Preparation complete. Driver start skipped (--prepare-only).")
				return nil
			}

			client, err := vck.Open()
			if err != nil {
				return fmt.Errorf("OS volume preparation completed, but driver connection failed: %w", err)
			}
			defer client.Close()

			// Write the JVCK footer metadata via IOCTL_JVCK_PREPARE. The block is
			// encrypted with the FIXED OS VMK (the same one written to vck.json), so
			// the loader/driver can recover the FVEK from the footer on the next
			// boot. The driver writes the replicas below its AddDevice filter, which
			// works on the live OS volume without lock/dismount.
			vmk, err := hex.DecodeString(osVolumeVmkHex)
			if err != nil {
				return fmt.Errorf("failed to decode fixed OS volume VMK: %w", err)
			}
			metadataBlock, err := buildOSVolumeMetadataBlock(prepareResult.VolumePath, vmk)
			if err != nil {
				return err
			}
			ntDevicePath, err := vck.VolumeNTDevicePath(prepareResult.VolumePath)
			if err != nil {
				return fmt.Errorf("failed to resolve NT device path: %w", err)
			}
			fmt.Println("Writing JVCK footer metadata (IOCTL_JVCK_PREPARE)...")
			prepResp, err := client.Prepare(&vck.JvckVolumePrepareRequest{
				VolumePath:    prepareResult.VolumePath,
				NTDevicePath:  ntDevicePath,
				UseHeader:     0,
				UseFooter:     osVolumeFooterReplicaCount,
				MetadataSize:  osVolumeMetadataSize,
				VMK:           vmk,
				MetadataBlock: metadataBlock,
				IsOsVolume:    true,
			})
			if err != nil {
				return fmt.Errorf("OS volume metadata prepare failed: %w", err)
			}
			fmt.Printf("Metadata written. offset_sector=%d data_sectors=%d sector_size=%d fully_attached=%t\n",
				prepResp.OffsetSector, prepResp.DataSectors, prepResp.SectorSize, prepResp.FullyAttached)

			if err := client.StartEncrypt(&vck.EncryptRequest{
				VolumePath: prepareResult.VolumePath,
			}); err != nil {
				return fmt.Errorf("OS volume encryption start failed: %w", err)
			}

			// --no-wait: return as soon as the sweep is started, leaving the
			// volume partially encrypted. Used by the reboot-through-loader test
			// (the blocking WatchProgress below would prevent the test from
			// rebooting while encryption is in progress).
			if osVolumeNoWait {
				fmt.Println("Encryption started (running in background; --no-wait).")
				return nil
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			evCh, errCh := client.WatchProgress(ctx, prepareResult.VolumePath)
			for ev := range evCh {
				fmt.Printf("\rEncrypting: %.1f%% (%d / %d sectors)",
					ev.ProgressPercent(), ev.EncryptedSector, ev.TotalSectors)
			}
			if err := <-errCh; err != nil {
				return err
			}
			fmt.Println("\nEncryption complete.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&osVolumePrepareOnly, "prepare-only", false, "perform shrink/EFI/vck.json preparation only")
	cmd.Flags().BoolVar(&osVolumeNoWait, "no-wait", false, "start encryption and return immediately (do not wait for completion)")
	return cmd
}

func newOSVolumeVerifyPrepareCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-prepare",
		Short: "verify EFI artifacts created for first-time OS volume encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := verifyPreparedOSVolume(effectiveOSVolumePath())
			if err != nil {
				return err
			}

			fmt.Printf("Verified OS volume preparation for %s\n", result.VolumePath)
			fmt.Printf("Partition GUID : %s\n", result.PartitionGUID)
			fmt.Printf("Config path    : %s\n", result.VckJSONPath)
			fmt.Printf("Boot copy path : %s\n", result.BootCopyPath)
			return nil
		},
	}
}

func effectiveOSVolumePath() string {
	if strings.TrimSpace(volumeFlag) == "" {
		return `\\.\C:`
	}
	return volumeFlag
}

func prepareOSVolume(volumePath string) (*osVolumePrepareResult, error) {
	vmkBytes, err := hex.DecodeString(osVolumeVmkHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode fixed OS volume VMK: %w", err)
	}

	volumePath = effectiveOSVolumePathFrom(volumePath)
	driveLetter, err := driveLetterFromVolumePath(volumePath)
	if err != nil {
		return nil, err
	}

	espMountPoint, err := mountESP()
	if err != nil {
		return nil, err
	}
	defer unmountESP(espMountPoint)

	bootCopyPath := filepath.Join(espMountPoint, `EFI\Microsoft\Boot\bootmgfw.os.efi`)
	vckJSONPath := filepath.Join(espMountPoint, `vck.json`)

	if _, err := os.Stat(vckJSONPath); err == nil {
		return nil, fmt.Errorf("OS volume appears to be prepared already: %s exists", vckJSONPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to inspect %s: %w", vckJSONPath, err)
	}

	volumeLength, _, err := readVolumeLengthAndSectorSize(volumePath)
	if err != nil {
		return nil, err
	}

	reservedBytes := uint64(osVolumeFooterReplicaCount) * uint64(osVolumeMetadataSize)
	targetSize := volumeLength - int64(reservedBytes)
	if targetSize <= 0 {
		return nil, fmt.Errorf("target size became non-positive after footer reservation")
	}
	if err := vck.ShrinkVolumeTail(volumePath, reservedBytes); err != nil {
		return nil, err
	}

	srcBootPath := filepath.Join(espMountPoint, `EFI\Microsoft\Boot\bootmgfw.efi`)
	if err := copyFile(srcBootPath, bootCopyPath); err != nil {
		return nil, err
	}

	partitionGUID, err := readPartitionGUID(volumePath)
	if err != nil {
		return nil, err
	}

	configBytes, err := json.Marshal(osVolumeConfig{
		PartitionGUID: partitionGUID,
		VMK:           base64.StdEncoding.EncodeToString(vmkBytes),
		OsLoader:      osVolumeOsLoader,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to serialize vck.json: %w", err)
	}
	if err := os.WriteFile(vckJSONPath, append(configBytes, '\n'), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", vckJSONPath, err)
	}

	return &osVolumePrepareResult{
		VolumePath:    volumePath,
		DriveLetter:   driveLetter,
		PartitionGUID: partitionGUID,
		ReservedBytes: reservedBytes,
		TargetSize:    uint64(targetSize),
		OsLoader:      osVolumeOsLoader,
		VckJSONPath:   vckJSONPath,
		BootCopyPath:  bootCopyPath,
	}, nil
}

func verifyPreparedOSVolume(volumePath string) (*osVolumePrepareResult, error) {
	vmkBytes, err := hex.DecodeString(osVolumeVmkHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode fixed OS volume VMK: %w", err)
	}

	volumePath = effectiveOSVolumePathFrom(volumePath)
	driveLetter, err := driveLetterFromVolumePath(volumePath)
	if err != nil {
		return nil, err
	}

	espMountPoint, err := mountESP()
	if err != nil {
		return nil, err
	}
	defer unmountESP(espMountPoint)

	bootCopyPath := filepath.Join(espMountPoint, `EFI\Microsoft\Boot\bootmgfw.os.efi`)
	vckJSONPath := filepath.Join(espMountPoint, `vck.json`)

	if _, err := os.Stat(bootCopyPath); err != nil {
		return nil, fmt.Errorf("prepared OS loader copy is missing: %w", err)
	}

	configBytes, err := os.ReadFile(vckJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", vckJSONPath, err)
	}

	var config osVolumeConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", vckJSONPath, err)
	}

	expectedVMK := base64.StdEncoding.EncodeToString(vmkBytes)
	if config.OsLoader != osVolumeOsLoader {
		return nil, fmt.Errorf("unexpected osloader in vck.json: %s", config.OsLoader)
	}
	if config.VMK != expectedVMK {
		return nil, fmt.Errorf("unexpected vmk in vck.json")
	}
	if strings.TrimSpace(config.PartitionGUID) == "" {
		return nil, fmt.Errorf("partition_guid is missing in vck.json")
	}

	return &osVolumePrepareResult{
		VolumePath:    volumePath,
		DriveLetter:   driveLetter,
		PartitionGUID: config.PartitionGUID,
		ReservedBytes: uint64(osVolumeFooterReplicaCount) * uint64(osVolumeMetadataSize),
		OsLoader:      config.OsLoader,
		VckJSONPath:   vckJSONPath,
		BootCopyPath:  bootCopyPath,
	}, nil
}

// buildOSVolumeMetadataBlock builds the 512-byte JVCK footer metadata block for
// the OS volume, encrypted with the fixed OS `vmk`. A freshly generated FVEK and
// volume ID are embedded; `encrypted_offset` starts at 0 so the sweep encrypts
// from the first data sector. If metadata already exists on the volume (re-run),
// an empty block is returned so the driver skips the write.
func buildOSVolumeMetadataBlock(volumePath string, vmk []byte) ([]byte, error) {
	length, sectorSize, err := vck.VolumeLengthAndSectorSize(volumePath)
	if err != nil {
		return nil, fmt.Errorf("failed to query volume geometry: %w", err)
	}
	exists, err := vck.HasJvckMetadata(volumePath, uint64(length), sectorSize)
	if err != nil {
		return nil, fmt.Errorf("failed to probe existing metadata: %w", err)
	}
	if exists {
		fmt.Println("Existing JVCK metadata found; reusing it (skip write).")
		return nil, nil
	}

	var fvek1, fvek2 [32]byte
	var volumeID [16]byte
	if _, err := rand.Read(fvek1[:]); err != nil {
		return nil, fmt.Errorf("failed to generate FVEK: %w", err)
	}
	if _, err := rand.Read(fvek2[:]); err != nil {
		return nil, fmt.Errorf("failed to generate FVEK: %w", err)
	}
	if _, err := rand.Read(volumeID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate volume ID: %w", err)
	}
	header := &vck.JvckHeader{
		MetadataVersion:    1,
		MetadataSize:       osVolumeMetadataSize,
		SectorSize:         sectorSize,
		HeaderReplicaCount: 0,
		FooterReplicaCount: osVolumeFooterReplicaCount,
		VolumeID:           volumeID,
	}
	block, err := header.EncodeMetadataBlock(fvek1, fvek2, 0, vmk)
	if err != nil {
		return nil, fmt.Errorf("failed to encode JVCK metadata: %w", err)
	}
	return block[:], nil
}

func effectiveOSVolumePathFrom(value string) string {
	if strings.TrimSpace(value) == "" {
		return `\\.\C:`
	}
	return value
}

// driveLetterFromVolumePath extracts a best-effort drive letter for display
// only (the result is informational and not used for any volume operation).
//
// The global --volume flag is normalized to a canonical volume GUID path
// (`\\?\Volume{GUID}\`) by root.go's PersistentPreRunE, so by the time the
// os-volume command runs the path is usually NOT a drive-letter form. Unknown
// formats (including GUID paths) return "" without error.
func driveLetterFromVolumePath(volumePath string) (string, error) {
	trimmed := strings.TrimSpace(volumePath)
	switch {
	case len(trimmed) >= 2 && trimmed[1] == ':':
		return strings.ToUpper(trimmed[:1]), nil
	case len(trimmed) >= 6 && strings.HasPrefix(trimmed, `\\.\`) && trimmed[5] == ':':
		return strings.ToUpper(trimmed[4:5]), nil
	default:
		// Canonical volume GUID path or other form — no drive letter to show.
		return "", nil
	}
}

func mountESP() (string, error) {
	mountPoint := `S:\`
	if _, err := os.Stat(mountPoint); err == nil {
		return "", fmt.Errorf("temporary EFI mount point %s is already in use", mountPoint)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to inspect %s: %w", mountPoint, err)
	}

	cmd := exec.Command("mountvol.exe", strings.TrimRight(mountPoint, `\`), "/S")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to mount EFI system partition: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	return mountPoint, nil
}

func unmountESP(mountPoint string) {
	_ = exec.Command("mountvol.exe", strings.TrimRight(mountPoint, `\`), "/D").Run()
}

func copyFile(src string, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", src, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("failed to create parent directory for %s: %w", dst, err)
	}

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", dst, err)
	}
	defer out.Close()

	if _, err := out.ReadFrom(in); err != nil {
		return fmt.Errorf("failed to copy %s to %s: %w", src, dst, err)
	}
	return nil
}

func readPartitionGUID(volumePath string) (string, error) {
	handle, err := openVolumeHandle(volumePath, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	var info partitionInformationEx
	var bytesReturned uint32
	err = windows.DeviceIoControl(
		handle,
		ioctlDiskGetPartitionInfoEx,
		nil,
		0,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to read partition info: %w", err)
	}
	if info.PartitionStyle != partitionStyleGPT {
		return "", fmt.Errorf("target OS volume is not on a GPT partition")
	}
	return formatGUID(info.Gpt.PartitionID), nil
}

func readVolumeLengthAndSectorSize(volumePath string) (int64, uint32, error) {
	return vck.VolumeLengthAndSectorSize(volumePath)
}

func openVolumeHandle(volumePath string, access uint32) (windows.Handle, error) {
	if access == 0 {
		access = windows.GENERIC_READ
	}

	// The --volume flag is canonicalized to "\\?\Volume{GUID}\" (filesystem
	// form); convert to the raw device-open form for CreateFile.
	devicePath, err := vck.VolumeDeviceOpenPath(volumePath)
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

func formatGUID(guid windows.GUID) string {
	return strings.ToLower(fmt.Sprintf(
		"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		guid.Data1,
		guid.Data2,
		guid.Data3,
		guid.Data4[0],
		guid.Data4[1],
		guid.Data4[2],
		guid.Data4[3],
		guid.Data4[4],
		guid.Data4[5],
		guid.Data4[6],
		guid.Data4[7],
	))
}
