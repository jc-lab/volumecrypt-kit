package cmd

import (
	"fmt"
	"os"

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

	// data-volume attach flags.
	attachCmd.Flags().StringVar(&vmkFlag, "vmk", "", "base64-encoded VMK")
	attachCmd.Flags().Uint32Var(&useHeaderFlag, "use-header", 0, "number of header metadata replicas")
	attachCmd.Flags().Uint32Var(&useFooterFlag, "use-footer", 2, "number of footer metadata replicas")
	attachCmd.Flags().Uint32Var(&metadataSizeFlag, "metadata-size", 131072, "size of a single replica region in bytes (min 128KiB)")

	// data-volume subcommands.
	dataVolumeCmd.AddCommand(attachCmd)
	dataVolumeCmd.AddCommand(newEncryptCmd())

	// os-volume subcommands.
	osVolumeCmd.AddCommand(newOSVolumeEncryptCmd())
	osVolumeCmd.AddCommand(newOSVolumeVerifyPrepareCmd())

	// Top-level command groups.
	rootCmd.AddCommand(osVolumeCmd)
	rootCmd.AddCommand(dataVolumeCmd)

	// Top-level convenience commands (as shown in the ARCH examples).
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(statusCmd)
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
