package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

var attachCmd = &cobra.Command{
	Use:   "attach",
	Short: "attach a Data Volume using the default JVCK format",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: validate that --vmk is provided and well-formed before use.
		vmk, err := base64.StdEncoding.DecodeString(vmkFlag)
		if err != nil {
			return fmt.Errorf("invalid base64 VMK: %w", err)
		}

		if useFooterFlag == 0 || metadataSizeFlag == 0 {
			return fmt.Errorf("--use-footer and --metadata-size must be greater than zero")
		}

		// Phase 0: reserve space at the volume tail (NTFS shrink).
		reserved := uint64(useFooterFlag) * uint64(metadataSizeFlag)
		fmt.Printf("Reserving %d bytes at the volume tail for footer metadata...\n", reserved)
		if err := vck.ShrinkVolumeTail(volumeFlag, reserved); err != nil {
			return fmt.Errorf("failed to reserve volume tail: %w", err)
		}

		// Resolve the NT device path for the driver.
		ntDevicePath, err := vck.VolumeNTDevicePath(volumeFlag)
		if err != nil {
			return fmt.Errorf("failed to resolve NT device path: %w", err)
		}
		fmt.Printf("NT device path: %s\n", ntDevicePath)

		client, err := vck.Open()
		if err != nil {
			return fmt.Errorf("failed to connect to driver: %w", err)
		}
		defer client.Close()

		// Phase 1: build JVCK metadata block (app is responsible for key generation
		// and crypto; driver just writes the provided binary to the footer).
		// For re-attach, send an empty MetadataBlock so the driver skips writing.
		fmt.Println("Phase 1: building JVCK metadata block...")
		var metadataBlock []byte
		{
			// Check if metadata already exists before generating a new one.
			length, sectorSize, gErr := vck.VolumeLengthAndSectorSize(volumeFlag)
			if gErr != nil {
				return fmt.Errorf("failed to query volume geometry: %w", gErr)
			}
			alreadyExists, checkErr := vck.HasJvckMetadata(volumeFlag, uint64(length), sectorSize)
			if checkErr != nil {
				return fmt.Errorf("failed to probe existing metadata: %w", checkErr)
			}
			if alreadyExists {
				fmt.Println("Existing JVCK metadata found; reusing it (skip write).")
				// Empty block → driver skips write.
			} else {
				fmt.Println("No metadata found; generating fresh FVEK + volume ID.")
				var fvek1, fvek2 [32]byte
				var volumeID [16]byte
				if _, err := rand.Read(fvek1[:]); err != nil {
					return fmt.Errorf("failed to generate FVEK: %w", err)
				}
				if _, err := rand.Read(fvek2[:]); err != nil {
					return fmt.Errorf("failed to generate FVEK: %w", err)
				}
				if _, err := rand.Read(volumeID[:]); err != nil {
					return fmt.Errorf("failed to generate volume ID: %w", err)
				}
				header := &vck.JvckHeader{
					MetadataVersion:    1,
					MetadataSize:       metadataSizeFlag,
					SectorSize:         uint32(sectorSize),
					HeaderReplicaCount: uint8(useHeaderFlag),
					FooterReplicaCount: uint8(useFooterFlag),
					VolumeID:           volumeID,
				}
				// encrypted_offset=1 so the driver knows sector 0 will be
				// pre-encrypted during PREPARE and the sweep starts from sector 1.
				block, encErr := header.EncodeMetadataBlock(fvek1, fvek2, 1, vmk)
				if encErr != nil {
					return fmt.Errorf("failed to encode JVCK metadata: %w", encErr)
				}
				metadataBlock = block[:]
			}
		}

		// Phase 2: driver attaches filter below FSD, writes metadata (while locked),
		// activates size hiding, then unlocks → NTFS remounts above filter with
		// only the data region visible. NTFS VBR backup goes to the last *visible*
		// sector (inside NTFS extent), never into the metadata region.
		fmt.Println("Phase 2: attaching filter + hiding metadata region...")
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
		fmt.Printf("Phase 2 done. offset=%d data=%d sector_size=%d\n",
			prepResp.OffsetSector, prepResp.DataSectors, prepResp.SectorSize)

		// If PREPARE completed full attach (VMK was provided), we're done.
		// Otherwise (re-attach of existing volume), call Attach separately.
		if prepResp.FullyAttached {
			fmt.Printf("Fully attached via PREPARE. offset=%d data=%d sector_size=%d\n",
				prepResp.OffsetSector, prepResp.DataSectors, prepResp.SectorSize)
		} else {
			fmt.Println("Phase 3: completing attach (reading metadata + deriving keys)...")
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
		}
		return nil
	},
}
