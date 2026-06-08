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
