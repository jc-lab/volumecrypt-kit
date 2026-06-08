package cmd

import (
	"context"
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "start incremental decryption of an attached volume",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vck.Open()
		if err != nil {
			return fmt.Errorf("failed to connect to driver: %w", err)
		}
		defer client.Close()

		if err := client.StartDecrypt(&vck.DecryptRequest{
			VolumePath: volumeFlag,
		}); err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		evCh, errCh := client.WatchProgress(ctx, volumeFlag)
		for ev := range evCh {
			fmt.Printf("\rDecrypting: %.1f%% (%d / %d sectors)",
				ev.ProgressPercent(), ev.EncryptedSector, ev.TotalSectors)
		}
		if err := <-errCh; err != nil {
			return err
		}
		fmt.Println("\nDecryption complete.")
		return nil
	},
}
