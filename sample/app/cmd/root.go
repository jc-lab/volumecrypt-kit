// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

// Global flags shared across subcommands.
var (
	// volumeFlag is the target volume path (persistent --volume flag).
	volumeFlag string

	// data-volume attach flags.
	vmkFlag          string
	useHeaderFlag    uint32
	useFooterFlag    uint32
	metadataSizeFlag uint32
)

var rootCmd = &cobra.Command{
	Use:   "vck-app",
	Short: "VolumeCryptKit sample management CLI",
	Long:  "vck-app manages OS/Data volume attach, encryption, decryption, and status via the VolumeCryptKit driver.",
	// Normalize --volume (accepts "D:", "\\.\D:", "\\?\Volume{GUID}") to the
	// canonical volume GUID path used for display and as the driver key.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if volumeFlag == "" {
			return nil
		}
		canonical, err := vck.CanonicalVolumePath(volumeFlag)
		if err != nil {
			return fmt.Errorf("invalid --volume %q: %w", volumeFlag, err)
		}
		volumeFlag = canonical
		return nil
	},
}

// osVolumeCmd groups OS volume subcommands.
var osVolumeCmd = &cobra.Command{
	Use:   "os-volume",
	Short: "OS (system) volume operations",
}

// dataVolumeCmd groups Data volume subcommands.
var dataVolumeCmd = &cobra.Command{
	Use:   "data-volume",
	Short: "Data volume operations",
}

func init() {
	rootCmd.PersistentFlags().StringVar(&volumeFlag, "volume", "", "target volume path (e.g. \\\\.\\D:)")

	// data-volume key/layout flags (shared by prepare + attach).
	for _, c := range []*cobra.Command{prepareCmd, attachCmd} {
		c.Flags().StringVar(&vmkFlag, "vmk", "", "base64-encoded VMK")
		c.Flags().Uint32Var(&useHeaderFlag, "use-header", 0, "number of header metadata replicas")
		c.Flags().Uint32Var(&useFooterFlag, "use-footer", 2, "number of footer metadata replicas")
		c.Flags().Uint32Var(&metadataSizeFlag, "metadata-size", 131072, "size of a single replica region in bytes (min 128KiB)")
	}

	// data-volume: prepare (first-time write+attach), attach (mount), detach
	// (dismount), encrypt/decrypt (sweep).
	dataVolumeCmd.AddCommand(prepareCmd)
	dataVolumeCmd.AddCommand(attachCmd)
	dataVolumeCmd.AddCommand(detachCmd)
	dataVolumeCmd.AddCommand(newEncryptCmd())
	dataVolumeCmd.AddCommand(newDecryptCmd())

	// os-volume: prepare (shrink/EFI/metadata), encrypt/decrypt (sweep).
	osVolumeCmd.AddCommand(newOSVolumePrepareCmd())
	osVolumeCmd.AddCommand(newEncryptCmd())
	osVolumeCmd.AddCommand(newDecryptCmd())
	osVolumeCmd.AddCommand(newOSVolumeVerifyPrepareCmd())

	// Top-level command groups.
	rootCmd.AddCommand(osVolumeCmd)
	rootCmd.AddCommand(dataVolumeCmd)

	// Top-level status query.
	rootCmd.AddCommand(statusCmd)
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
