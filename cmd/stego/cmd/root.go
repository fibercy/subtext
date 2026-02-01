// Package cmd implements the stego CLI commands.
package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	pb "github.com/cy/stegochat/proto"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	serverAddr string
	client     pb.StegoServiceClient
	conn       *grpc.ClientConn
)

// rootCmd is the base command
var rootCmd = &cobra.Command{
	Use:   "stego",
	Short: "Steganographic chat CLI",
	Long: `A CLI client for the steganographic chat daemon.

Encode secret messages into natural-looking cover text and decode them back.
Supports deniable encryption with decoy messages.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip connection for help commands
		if cmd.Name() == "help" || cmd.Name() == "version" {
			return nil
		}

		var err error
		conn, err = grpc.NewClient(serverAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			return fmt.Errorf("failed to connect to daemon: %w", err)
		}
		client = pb.NewStegoServiceClient(conn)
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if conn != nil {
			conn.Close()
		}
	},
}

// Execute runs the CLI
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "localhost:50051", "Daemon address")
}

// Helper function to get context with timeout
func getContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// Helper to print errors consistently
func exitError(msg string, err error) {
	fmt.Fprintf(os.Stderr, "Error: %s: %v\n", msg, err)
	os.Exit(1)
}
