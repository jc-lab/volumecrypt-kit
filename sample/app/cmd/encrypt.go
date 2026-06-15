// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

// newSweepCmd builds an "encrypt" or "decrypt" subcommand that starts the
// background sweep on an already-attached volume and (unless --no-wait) streams
// progress. A fresh instance is created per parent group (os-volume /
// data-volume) because a cobra command may only attach to one parent.
//
// Attach/prepare is a separate step: encryption only starts the sweep; the
// volume must already be prepared (OS) or attached (data).
func newSweepCmd(decrypt bool) *cobra.Command {
	var noWait bool
	verb := "encryption"
	gerund := "Encrypting"
	use := "encrypt"
	if decrypt {
		verb, gerund, use = "decryption", "Decrypting", "decrypt"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: fmt.Sprintf("start incremental %s of an attached volume", verb),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := vck.Open()
			if err != nil {
				return fmt.Errorf("failed to connect to driver: %w", err)
			}
			defer client.Close()

			if decrypt {
				err = client.StartDecrypt(&vck.DecryptRequest{VolumePath: volumeFlag})
			} else {
				err = client.StartEncrypt(&vck.EncryptRequest{VolumePath: volumeFlag})
			}
			if err != nil {
				return err
			}

			if noWait {
				fmt.Printf("%s started (running in background; --no-wait).\n", gerund)
				return nil
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			evCh, errCh := client.WatchProgress(ctx, volumeFlag)
			for ev := range evCh {
				fmt.Printf("\r%s: %.1f%% (%d / %d sectors)",
					gerund, ev.ProgressPercent(), ev.EncryptedSector, ev.TotalSectors)
			}
			if err := <-errCh; err != nil {
				return err
			}
			fmt.Printf("\n%s complete.\n", gerund)
			return nil
		},
	}
	cmd.Flags().BoolVar(&noWait, "no-wait", false, "start the sweep and return immediately (do not wait for completion)")
	return cmd
}

// newEncryptCmd / newDecryptCmd build the generic sweep commands attached under
// both os-volume and data-volume.
func newEncryptCmd() *cobra.Command { return newSweepCmd(false) }
func newDecryptCmd() *cobra.Command { return newSweepCmd(true) }
