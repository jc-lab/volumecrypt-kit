// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

// prepareCmd (data-volume prepare): FIRST-TIME setup of a data volume — reserve
// the footer region (shrink), write fresh JVCK metadata, and attach (mount) the
// encryption filter. Run once per volume; afterwards use `attach`/`detach`.
var prepareCmd = &cobra.Command{
	Use:   "prepare",
	Short: "first-time prepare (write JVCK metadata) + attach a Data Volume",
	RunE: func(cmd *cobra.Command, args []string) error {
		vmk, err := base64.StdEncoding.DecodeString(vmkFlag)
		if err != nil {
			return fmt.Errorf("invalid base64 VMK: %w", err)
		}
		if useFooterFlag == 0 || metadataSizeFlag == 0 {
			return fmt.Errorf("--use-footer and --metadata-size must be greater than zero")
		}

		// Reserve space at the volume tail (NTFS shrink) for the footer metadata.
		reserved := uint64(useFooterFlag) * uint64(metadataSizeFlag)
		fmt.Printf("Reserving %d bytes at the volume tail for footer metadata...\n", reserved)
		if err := vck.ShrinkVolumeTail(volumeFlag, reserved); err != nil {
			return fmt.Errorf("failed to reserve volume tail: %w", err)
		}

		ntDevicePath, err := vck.VolumeNTDevicePath(volumeFlag)
		if err != nil {
			return fmt.Errorf("failed to resolve NT device path: %w", err)
		}
		fmt.Printf("NT device path: %s\n", ntDevicePath)

		// Build the JVCK metadata block (app owns key generation + crypto). If
		// metadata already exists, send an empty block so the driver skips the write.
		metadataBlock, err := buildDataVolumeMetadataBlock(volumeFlag, vmk)
		if err != nil {
			return err
		}
		return attachViaDriver(ntDevicePath, vmk, metadataBlock)
	},
}

// attachCmd (data-volume attach = MOUNT): re-attach an already-prepared volume
// (e.g. after reboot). No shrink and no metadata generation — the driver reads
// the existing footer metadata with the VMK and activates the layer.
var attachCmd = &cobra.Command{
	Use:   "attach",
	Short: "attach (mount) an already-prepared Data Volume",
	RunE: func(cmd *cobra.Command, args []string) error {
		vmk, err := base64.StdEncoding.DecodeString(vmkFlag)
		if err != nil {
			return fmt.Errorf("invalid base64 VMK: %w", err)
		}
		ntDevicePath, err := vck.VolumeNTDevicePath(volumeFlag)
		if err != nil {
			return fmt.Errorf("failed to resolve NT device path: %w", err)
		}
		fmt.Printf("NT device path: %s\n", ntDevicePath)
		// Empty metadata block → driver never writes; it only reads existing metadata.
		return attachViaDriver(ntDevicePath, vmk, nil)
	},
}

// buildDataVolumeMetadataBlock returns the 512-byte JVCK metadata block for a
// first-time prepare, or nil (skip write) if metadata already exists.
func buildDataVolumeMetadataBlock(volumePath string, vmk []byte) ([]byte, error) {
	length, sectorSize, gErr := vck.VolumeLengthAndSectorSize(volumePath)
	if gErr != nil {
		return nil, fmt.Errorf("failed to query volume geometry: %w", gErr)
	}
	exists, checkErr := vck.HasJvckMetadata(volumePath, uint64(length), sectorSize)
	if checkErr != nil {
		return nil, fmt.Errorf("failed to probe existing metadata: %w", checkErr)
	}
	if exists {
		fmt.Println("Existing JVCK metadata found; reusing it (skip write).")
		return nil, nil
	}
	fmt.Println("No metadata found; generating fresh FVEK + volume ID.")
	var fvek1, fvek2 [32]byte
	var volumeID [16]byte
	var salt [vck.SaltSize]byte
	for _, b := range [][]byte{fvek1[:], fvek2[:], volumeID[:], salt[:]} {
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("failed to generate key material: %w", err)
		}
	}
	header := &vck.JvckHeader{
		MetadataVersion:    1,
		MetadataSize:       metadataSizeFlag,
		SectorSize:         uint32(sectorSize),
		HeaderReplicaCount: uint8(useHeaderFlag),
		FooterReplicaCount: uint8(useFooterFlag),
		VolumeID:           volumeID,
	}
	// encrypted_offset=0: sweep starts from sector 0.
	block, encErr := header.EncodeMetadataBlock(fvek1, fvek2, 0, salt, vmk)
	if encErr != nil {
		return nil, fmt.Errorf("failed to encode JVCK metadata: %w", encErr)
	}
	return block[:], nil
}

// attachViaDriver runs the two-phase driver attach: PREPARE (filter bind + size
// hiding + optional metadata write) then ATTACH (read metadata + derive keys) if
// PREPARE did not already complete the full attach.
func attachViaDriver(ntDevicePath string, vmk []byte, metadataBlock []byte) error {
	client, err := vck.Open()
	if err != nil {
		return fmt.Errorf("failed to connect to driver: %w", err)
	}
	defer client.Close()

	fmt.Println("Phase 1: attaching filter + hiding metadata region...")
	prepResp, err := client.Prepare(&vck.JvckVolumePrepareRequest{
		VolumePath:    volumeFlag,
		NTDevicePath:  ntDevicePath,
		UseHeader:     useHeaderFlag,
		UseFooter:     useFooterFlag,
		MetadataSize:  metadataSizeFlag,
		VMK:           vmk,
		MetadataBlock: metadataBlock,
	})
	if err != nil {
		return fmt.Errorf("prepare failed: %w", err)
	}

	if prepResp.FullyAttached {
		fmt.Printf("Fully attached via PREPARE. offset=%d data=%d sector_size=%d\n",
			prepResp.OffsetSector, prepResp.DataSectors, prepResp.SectorSize)
		return nil
	}
	fmt.Println("Phase 2: completing attach (reading metadata + deriving keys)...")
	resp, err := client.Attach(&vck.JvckVolumeAttachRequest{
		VolumePath:   volumeFlag,
		VMK:          vmk,
		NTDevicePath: ntDevicePath,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Attached. offset_sector=%d total_sectors=%d sector_size=%d\n",
		resp.OffsetSector, resp.TotalSectors, resp.SectorSize)
	return nil
}
