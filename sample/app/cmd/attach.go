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

		// Reserve space at the volume tail for the footer metadata replicas so
		// the filesystem no longer occupies it. Existing data volumes cannot use
		// a header, so only the footer region is reserved. ShrinkVolumeTail
		// targets an absolute size, so it is a no-op on re-attach.
		reserved := uint64(useFooterFlag) * uint64(metadataSizeFlag)
		if reserved == 0 {
			return fmt.Errorf("--use-footer and --metadata-size must be greater than zero")
		}
		fmt.Printf("Reserving %d bytes at the volume tail for footer metadata...\n", reserved)
		if err := vck.ShrinkVolumeTail(volumeFlag, reserved); err != nil {
			return fmt.Errorf("failed to reserve volume tail: %w", err)
		}

		// First-time encryption: generate the FVEK + volume id and write the JVCK
		// footer metadata into the reserved tail (over an extended-DASD handle).
		// A no-op when the volume already carries metadata (re-attach).
		created, err := vck.EnsureJvckMetadata(volumeFlag, vmk, useHeaderFlag, useFooterFlag, metadataSizeFlag)
		if err != nil {
			return fmt.Errorf("failed to write JVCK metadata: %w", err)
		}
		if created {
			fmt.Println("Wrote fresh JVCK metadata (first-time encryption).")
		} else {
			fmt.Println("Existing JVCK metadata found; reusing it.")
		}

		client, err := vck.Open()
		if err != nil {
			return fmt.Errorf("failed to connect to driver: %w", err)
		}
		defer client.Close()

		resp, err := client.Attach(&vck.JvckVolumeAttachRequest{
			VolumePath:   volumeFlag,
			VMK:          vmk,
			UseHeader:    useHeaderFlag,
			UseFooter:    useFooterFlag,
			MetadataSize: metadataSizeFlag,
		})
		if err != nil {
			return err
		}

		fmt.Printf("Attached. offset_sector=%d total_sectors=%d sector_size=%d\n",
			resp.OffsetSector, resp.TotalSectors, resp.SectorSize)
		return nil
	},
}
