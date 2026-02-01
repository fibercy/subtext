package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"text/tabwriter"

	pb "github.com/cy/stegochat/proto"
	"github.com/spf13/cobra"
)

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Manage chat sessions",
}

var sessionCreateCmd = &cobra.Command{
	Use:   "create <peer-id>",
	Short: "Create a new session with a peer",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		peerID := args[0]
		displayName, _ := cmd.Flags().GetString("name")

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.CreateSession(ctx, &pb.CreateSessionRequest{
			PeerId:      peerID,
			DisplayName: displayName,
		})
		if err != nil {
			exitError("failed to create session", err)
		}

		fmt.Printf("Session created:\n")
		fmt.Printf("  ID:      %s\n", resp.Id)
		fmt.Printf("  Peer:    %s\n", resp.PeerId)
		fmt.Printf("  Name:    %s\n", resp.DisplayName)
		fmt.Printf("  State:   %s\n", resp.State.String())
	},
}

var sessionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all sessions",
	Run: func(cmd *cobra.Command, args []string) {
		limit, _ := cmd.Flags().GetInt32("limit")

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.ListSessions(ctx, &pb.ListSessionsRequest{
			Limit: limit,
		})
		if err != nil {
			exitError("failed to list sessions", err)
		}

		if len(resp.Sessions) == 0 {
			fmt.Println("No sessions found.")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tPEER\tNAME\tSTATE")
		fmt.Fprintln(w, "──\t────\t────\t─────")
		for _, s := range resp.Sessions {
			shortID := s.Id[:8]
			state := stateShortName(s.State)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", shortID, s.PeerId, s.DisplayName, state)
		}
		w.Flush()

		fmt.Printf("\nTotal: %d sessions\n", resp.Total)
	},
}

var sessionGetCmd = &cobra.Command{
	Use:   "get <session-id>",
	Short: "Get session details",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := args[0]

		ctx, cancel := getContext()
		defer cancel()

		// Try to find session by prefix if short ID provided
		resp, err := client.GetSession(ctx, &pb.GetSessionRequest{
			SessionId: sessionID,
		})
		if err != nil {
			// Try listing and matching prefix
			listResp, listErr := client.ListSessions(ctx, &pb.ListSessionsRequest{Limit: 100})
			if listErr == nil {
				for _, s := range listResp.Sessions {
					if len(sessionID) >= 4 && s.Id[:len(sessionID)] == sessionID {
						resp, err = client.GetSession(ctx, &pb.GetSessionRequest{SessionId: s.Id})
						break
					}
				}
			}
		}
		if err != nil {
			exitError("failed to get session", err)
		}

		fmt.Printf("Session Details:\n")
		fmt.Printf("  ID:          %s\n", resp.Id)
		fmt.Printf("  Peer:        %s\n", resp.PeerId)
		fmt.Printf("  Display:     %s\n", resp.DisplayName)
		fmt.Printf("  State:       %s\n", resp.State.String())
	},
}

var sessionKeyExchangeCmd = &cobra.Command{
	Use:   "key-exchange <session-id>",
	Short: "Initiate key exchange (get public key)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := resolveSessionID(args[0])

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.InitiateKeyExchange(ctx, &pb.InitiateKeyExchangeRequest{
			SessionId: sessionID,
		})
		if err != nil {
			exitError("failed to initiate key exchange", err)
		}

		fmt.Printf("Your public key (share with peer):\n")
		fmt.Printf("%s\n", hex.EncodeToString(resp.PublicKey))
	},
}

var sessionCompleteKeyExchangeCmd = &cobra.Command{
	Use:   "complete-key-exchange <session-id> <peer-public-key>",
	Short: "Complete key exchange with peer's public key",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := resolveSessionID(args[0])
		peerKeyHex := args[1]

		peerKey, err := hex.DecodeString(peerKeyHex)
		if err != nil {
			exitError("invalid peer public key (must be hex)", err)
		}

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.CompleteKeyExchange(ctx, &pb.CompleteKeyExchangeRequest{
			SessionId:     sessionID,
			PeerPublicKey: peerKey,
		})
		if err != nil {
			exitError("key exchange failed", err)
		}

		if resp.Success {
			fmt.Println("✓ Key exchange complete! Session is now active.")
		} else {
			fmt.Printf("✗ Key exchange failed: %s\n", resp.ErrorMessage)
		}
	},
}

func init() {
	rootCmd.AddCommand(sessionCmd)
	sessionCmd.AddCommand(sessionCreateCmd)
	sessionCmd.AddCommand(sessionListCmd)
	sessionCmd.AddCommand(sessionGetCmd)
	sessionCmd.AddCommand(sessionKeyExchangeCmd)
	sessionCmd.AddCommand(sessionCompleteKeyExchangeCmd)

	sessionCreateCmd.Flags().StringP("name", "n", "", "Display name for the session")
	sessionListCmd.Flags().Int32P("limit", "l", 20, "Maximum sessions to list")
}

func stateShortName(state pb.SessionState) string {
	switch state {
	case pb.SessionState_SESSION_STATE_PENDING_KEY_EXCHANGE:
		return "pending"
	case pb.SessionState_SESSION_STATE_ACTIVE:
		return "active"
	case pb.SessionState_SESSION_STATE_EXPIRED:
		return "expired"
	default:
		return "unknown"
	}
}

// resolveSessionID tries to find full session ID from a prefix
func resolveSessionID(prefix string) string {
	if len(prefix) >= 36 {
		return prefix // Already full UUID
	}

	ctx, cancel := getContext()
	defer cancel()

	listResp, err := client.ListSessions(ctx, &pb.ListSessionsRequest{Limit: 100})
	if err != nil {
		return prefix
	}

	for _, s := range listResp.Sessions {
		if len(prefix) >= 4 && len(s.Id) >= len(prefix) && s.Id[:len(prefix)] == prefix {
			return s.Id
		}
	}

	return prefix
}
