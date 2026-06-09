package cmd

import (
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

		// Phase 1: driver attaches filter + activates size hiding.
		// NTFS remounts seeing only the data region → VBR backup goes to
		// the last visible sector (inside NTFS extent), NOT our footer.
		fmt.Println("Phase 1: attaching filter and hiding metadata region...")
		prepResp, err := client.Prepare(&vck.JvckVolumePrepareRequest{
			VolumePath:   volumeFlag,
			NTDevicePath: ntDevicePath,
			UseHeader:    useHeaderFlag,
			UseFooter:    useFooterFlag,
			MetadataSize: metadataSizeFlag,
		})
		if err != nil {
			return fmt.Errorf("prepare failed: %w", err)
		}
		fmt.Printf("Phase 1 done. offset=%d data=%d sector_size=%d\n",
			prepResp.OffsetSector, prepResp.DataSectors, prepResp.SectorSize)

		// Phase 2: write JVCK footer metadata. The metadata region is now hidden
		// from NTFS so NTFS cannot overwrite it with VBR backup data.
		fmt.Println("Phase 2: writing JVCK footer metadata...")
		created, err := vck.EnsureJvckMetadata(volumeFlag, vmk, useHeaderFlag, useFooterFlag, metadataSizeFlag)
		if err != nil {
			return fmt.Errorf("failed to write JVCK metadata: %w", err)
		}
		if created {
			fmt.Println("Wrote fresh JVCK metadata (first-time encryption).")
		} else {
			fmt.Println("Existing JVCK metadata found; reusing it.")
		}

		// Phase 3: driver reads the metadata and completes encryption setup.
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
		return nil
	},
}
