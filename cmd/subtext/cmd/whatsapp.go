package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cy/subtext/internal/whatsapp"
	"github.com/spf13/cobra"
)

var waCmd = &cobra.Command{
	Use:     "whatsapp",
	Short:   "WhatsApp bridge commands",
	Aliases: []string{"wa"},
}

var waConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to WhatsApp and start the bridge",
	Long: `Connect to WhatsApp using the whatsmeow bridge.

On first run, a QR code will be displayed for login.
After login, the bridge will:
- Automatically decode incoming messages from registered sessions
- Allow sending steganographic messages

Messages from contacts without registered sessions are passed through as-is.`,
	Run: func(cmd *cobra.Command, args []string) {
		dataDir, _ := cmd.Flags().GetString("data-dir")

		// Expand home directory
		if dataDir == "" {
			home, _ := os.UserHomeDir()
			dataDir = filepath.Join(home, ".stegochat")
		}

		// Ensure data directory exists
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			exitError("failed to create data directory", err)
		}

		dbPath := filepath.Join(dataDir, "whatsapp.db")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Create bridge
		bridge, err := whatsapp.NewBridge(ctx, whatsapp.BridgeConfig{
			DBPath:      dbPath,
			StegoClient: client,
			OnMessage: func(from, message string, isDecoded bool) {
				if isDecoded {
					fmt.Printf("\n📩 [%s] (DECODED): %s\n> ", from, message)
				} else {
					fmt.Printf("\n💬 [%s]: %s\n> ", from, message)
				}
			},
		})
		if err != nil {
			exitError("failed to create bridge", err)
		}
		defer bridge.Disconnect()

		fmt.Println("Connecting to WhatsApp...")
		if err := bridge.Connect(ctx); err != nil {
			exitError("failed to connect", err)
		}

		fmt.Println("\n✓ WhatsApp bridge running")

		// Run interactive mode
		bridge.RunInteractive(ctx)

		fmt.Println("Shutting down...")
	},
}

var waStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check WhatsApp connection status",
	Run: func(cmd *cobra.Command, args []string) {
		dataDir, _ := cmd.Flags().GetString("data-dir")

		if dataDir == "" {
			home, _ := os.UserHomeDir()
			dataDir = filepath.Join(home, ".stegochat")
		}

		dbPath := filepath.Join(dataDir, "whatsapp.db")

		// Check if database exists
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			fmt.Println("✗ WhatsApp not configured")
			fmt.Println("  Run 'stego whatsapp connect' to set up")
			return
		}

		ctx := context.Background()
		bridge, err := whatsapp.NewBridge(ctx, whatsapp.BridgeConfig{
			DBPath: dbPath,
		})
		if err != nil {
			fmt.Printf("✗ Error: %v\n", err)
			return
		}

		jid := bridge.GetJID()
		if jid != "" {
			fmt.Printf("✓ WhatsApp configured for: +%s\n", jid)
		} else {
			fmt.Println("✗ WhatsApp not logged in")
			fmt.Println("  Run 'stego whatsapp connect' to log in")
		}
	},
}

var waLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out from WhatsApp",
	Run: func(cmd *cobra.Command, args []string) {
		dataDir, _ := cmd.Flags().GetString("data-dir")

		if dataDir == "" {
			home, _ := os.UserHomeDir()
			dataDir = filepath.Join(home, ".stegochat")
		}

		dbPath := filepath.Join(dataDir, "whatsapp.db")

		// Simply delete the database
		if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
			exitError("failed to logout", err)
		}

		fmt.Println("✓ Logged out from WhatsApp")
	},
}

func init() {
	rootCmd.AddCommand(waCmd)
	waCmd.AddCommand(waConnectCmd)
	waCmd.AddCommand(waStatusCmd)
	waCmd.AddCommand(waLogoutCmd)

	waConnectCmd.Flags().String("data-dir", "", "Data directory (default: ~/.stegochat)")
	waStatusCmd.Flags().String("data-dir", "", "Data directory (default: ~/.stegochat)")
	waLogoutCmd.Flags().String("data-dir", "", "Data directory (default: ~/.stegochat)")
}
