// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
	"golang.org/x/sys/cpu"
)

var benchSizeFlag uint64

var benchAesCmd = &cobra.Command{
	Use:   "bench-aes",
	Short: "measure in-kernel AES-256-XTS encrypt/decrypt throughput",
	Long: `Runs an AES-256-XTS benchmark inside the kernel driver and prints
encrypt and decrypt throughput in MiB/s.

The driver allocates a 1 MiB NonPagedPool scratch buffer and processes
--size bytes per direction (default 1 GiB).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if cpu.X86.HasAES {
			fmt.Println("AES-NI   : supported")
		} else {
			fmt.Println("AES-NI   : not supported (software AES)")
		}

		client, err := vck.Open()
		if err != nil {
			return err
		}
		defer client.Close()

		resp, err := client.BenchAes(benchSizeFlag)
		if err != nil {
			return err
		}

		sizeMiB := resp.SizeBytes / (1024 * 1024)
		fmt.Printf("Size     : %d MiB\n", sizeMiB)
		fmt.Printf("Encrypt  : %d MiB/s\n", resp.EncryptMiBs)
		fmt.Printf("Decrypt  : %d MiB/s\n", resp.DecryptMiBs)
		return nil
	},
}

func init() {
	benchAesCmd.Flags().Uint64Var(&benchSizeFlag, "size", 0, "bytes to process per direction (0 = 1 GiB default)")
	rootCmd.AddCommand(benchAesCmd)
}
