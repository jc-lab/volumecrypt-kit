// SPDX-FileCopyrightText: 2026 JC-Lab <joseph@jc-lab.net>
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "query volume encryption status (lists all attached volumes when --volume is omitted)",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vck.Open()
		if err != nil {
			return err
		}
		defer client.Close()

		// No --volume: enumerate all attached volumes. This needs no volume path,
		// so it also serves as a driver-connection check (a successful call with
		// an empty list still confirms the driver is reachable).
		if volumeFlag == "" {
			return listAttachedVolumes(client)
		}

		// The SDK normalizes volume_path to the NT device path for every IOCTL,
		// so a query by the canonical Win32 path resolves both freshly-prepared
		// and handover-reattached (post-reboot) volumes.
		st, err := client.GetStatus(volumeFlag)
		if err != nil {
			return err
		}
		fmt.Printf("Volume   : %s (%s)\n", volumeFlag, st.VolumePath)
		fmt.Printf("State    : %d\n", st.State)
		fmt.Printf("Progress : %.2f%% (%d / %d sectors)\n",
			st.ProgressPercent(), st.EncryptedSector, st.TotalSectors)
		if st.FilterBelowFsd {
			fmt.Println("Filter   : below FSD (AddDevice) ✓")
		} else {
			fmt.Println("Filter   : NOT below FSD — reboot required for correct position")
		}
		return nil
	},
}

// listAttachedVolumes prints every volume currently attached to the driver.
func listAttachedVolumes(client *vck.Client) error {
	resp, err := client.ListVolumes()
	if err != nil {
		return err
	}
	fmt.Printf("Driver connected. Attached volumes: %d\n", len(resp.Volumes))
	for i, v := range resp.Volumes {
		kind := "data"
		if v.IsOsVolume {
			kind = "os"
		}
		fmt.Printf("  [%d] %s (%s)\n", i, v.VolumePath, kind)
		fmt.Printf("      State    : %d\n", v.State)
		fmt.Printf("      Progress : %.2f%% (%d / %d sectors, %d B/sector)\n",
			v.ProgressPercent(), v.EncryptedSector, v.TotalSectors, v.SectorSize)
	}
	return nil
}
