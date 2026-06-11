// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmd

import (
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(volumeInfoCmd)
}

// volumeInfoCmd reports the raw volume length + sector size as seen through the
// storage stack. When the VolumeCryptKit filter is attached, the reported length
// is the data-region size (partition minus header/footer metadata), proving the
// metadata regions are hidden from the OS.
var volumeInfoCmd = &cobra.Command{
	Use:   "volume-info",
	Short: "print the raw volume length and sector size (as the OS sees it)",
	RunE: func(cmd *cobra.Command, args []string) error {
		length, sectorSize, err := vck.VolumeLengthAndSectorSize(volumeFlag)
		if err != nil {
			return err
		}
		fmt.Printf("Volume      : %s\n", volumeFlag)
		fmt.Printf("Length      : %d bytes\n", length)
		fmt.Printf("SectorSize  : %d bytes\n", sectorSize)
		if sectorSize > 0 {
			fmt.Printf("Sectors     : %d\n", length/int64(sectorSize))
		}
		return nil
	},
}
