package cmd

import (
	"fmt"

	vck "github.com/jc-lab/volumecrypt-kit/sdk"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "query volume encryption status",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := vck.Open()
		if err != nil {
			return err
		}
		defer client.Close()

		st, err := client.GetStatus(volumeFlag)
		if err != nil {
			return err
		}
		fmt.Printf("Volume   : %s\n", st.VolumePath)
		fmt.Printf("State    : %d\n", st.State)
		fmt.Printf("Progress : %.2f%% (%d / %d sectors)\n",
			st.ProgressPercent(), st.EncryptedSector, st.TotalSectors)
		return nil
	},
}
