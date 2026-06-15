// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

var detachCmd = &cobra.Command{
	Use:   "detach",
	Short: "detach a Data Volume (remove the encryption filter)",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vck.Open()
		if err != nil {
			return fmt.Errorf("failed to connect to driver: %w", err)
		}
		defer client.Close()

		if err := client.Detach(volumeFlag); err != nil {
			return err
		}
		fmt.Printf("Detached %s\n", volumeFlag)
		return nil
	},
}
