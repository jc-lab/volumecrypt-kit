package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

// randomBytes returns n cryptographically-random bytes.
func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

var attachCmd = &cobra.Command{
	Use:   "attach",
	Short: "attach a Data Volume using the default JVCK format",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: validate that --vmk is provided and well-formed before use.
		vmk, err := base64.StdEncoding.DecodeString(vmkFlag)
		if err != nil {
			return fmt.Errorf("invalid base64 VMK: %w", err)
		}

		// Generate fresh FVEK + volume id for first-time encryption. The driver
		// ignores these when the volume already has JVCK metadata.
		fvek1, err := randomBytes(32)
		if err != nil {
			return fmt.Errorf("failed to generate FVEK: %w", err)
		}
		fvek2, err := randomBytes(32)
		if err != nil {
			return fmt.Errorf("failed to generate FVEK: %w", err)
		}
		volumeID, err := randomBytes(16)
		if err != nil {
			return fmt.Errorf("failed to generate volume id: %w", err)
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
			Fvek1:        fvek1,
			Fvek2:        fvek2,
			VolumeID:     volumeID,
		})
		if err != nil {
			return err
		}

		fmt.Printf("Attached. offset_sector=%d total_sectors=%d sector_size=%d\n",
			resp.OffsetSector, resp.TotalSectors, resp.SectorSize)
		return nil
	},
}
