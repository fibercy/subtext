package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("stego v0.1.0")
		fmt.Println("Steganographic chat CLI client")
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check daemon status",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := getContext()
		defer cancel()

		// Try to list sessions as a health check
		_, err := client.ListSessions(ctx, nil)
		if err != nil {
			fmt.Printf("✗ Daemon not reachable at %s\n", serverAddr)
			fmt.Printf("  Error: %v\n", err)
			fmt.Println("\n  Start the daemon with: stegod")
			return
		}

		fmt.Printf("✓ Daemon running at %s\n", serverAddr)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(statusCmd)
}
