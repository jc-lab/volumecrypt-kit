package cmd

import (
	"context"
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

// newEncryptCmd builds an "encrypt" subcommand. A fresh instance is created per
// parent group (os-volume / data-volume) because a cobra command may only be
// attached to a single parent.
func newEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt",
		Short: "start incremental encryption of an attached volume",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := vck.Open()
			if err != nil {
				return fmt.Errorf("failed to connect to driver: %w", err)
			}
			defer client.Close()

			if err := client.StartEncrypt(&vck.EncryptRequest{
				VolumePath: volumeFlag,
			}); err != nil {
				return err
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			evCh, errCh := client.WatchProgress(ctx, volumeFlag)
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
}
