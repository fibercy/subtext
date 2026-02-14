package cmd

import (
	"encoding/hex"
	"fmt"
	"strings"

	pb "github.com/cy/stegochat/proto"
	"github.com/spf13/cobra"
)

var encodeCmd = &cobra.Command{
	Use:   "encode <session-id> <secret-message>",
	Short: "Encode a secret message into cover text",
	Long: `Encode a secret message into natural-looking cover text.

The daemon must be connected to Ollama for actual LLM-based encoding.
Otherwise, a placeholder response is returned.

Examples:
  stego encode abc123 "Meet at 9pm"
  stego encode abc123 "Secret" --decoy "Coffee tomorrow?"
  stego encode abc123 "Secret" --topic "weekend plans"`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := resolveSessionID(args[0])
		secretMessage := args[1]
		decoyMessage, _ := cmd.Flags().GetString("decoy")
		topicHint, _ := cmd.Flags().GetString("topic")

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.EncodeMessage(ctx, &pb.EncodeMessageRequest{
			SessionId:     sessionID,
			SecretMessage: secretMessage,
			DecoyMessage:  decoyMessage,
			TopicHint:     topicHint,
		})
		if err != nil {
			exitError("encoding failed", err)
		}

		raw, _ := cmd.Flags().GetBool("raw")
		if raw {
			fmt.Print(resp.CoverText)
			return
		}

		fmt.Println("═══════════════════════════════════════")
		fmt.Println("COVER TEXT (send this to your peer):")
		fmt.Println("───────────────────────────────────────")
		fmt.Println(resp.CoverText)
		fmt.Println("═══════════════════════════════════════")
		fmt.Printf("\nBits encoded: %d\n", resp.BitsEncoded)
		fmt.Printf("Message ID:   %s\n", resp.MessageId)

		if decoyMessage != "" {
			fmt.Printf("\n⚠ Deniable encryption used. Decoy key stored for session.\n")
		}
	},
}

var decodeCmd = &cobra.Command{
	Use:   "decode <session-id> <cover-text>",
	Short: "Decode a secret message from cover text",
	Long: `Decode a secret message hidden in cover text.

Use --decoy-key to decode with a decoy key (reveals decoy message).

Examples:
  stego decode abc123 "Some natural looking text..."
  stego decode abc123 "..." --decoy-key <hex-key>`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := resolveSessionID(args[0])
		coverText := args[1]
		decoyKeyHex, _ := cmd.Flags().GetString("decoy-key")
		topicHint, _ := cmd.Flags().GetString("topic")

		var decoyKey []byte
		if decoyKeyHex != "" {
			var err error
			decoyKey, err = hex.DecodeString(decoyKeyHex)
			if err != nil {
				exitError("invalid decoy key (must be hex)", err)
			}
		}

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.DecodeMessage(ctx, &pb.DecodeMessageRequest{
			SessionId: sessionID,
			CoverText: coverText,
			DecoyKey:  decoyKey,
			TopicHint: topicHint,
		})
		if err != nil {
			exitError("decoding failed", err)
		}

		fmt.Println("═══════════════════════════════════════")
		fmt.Println("DECODED MESSAGE:")
		fmt.Println("───────────────────────────────────────")
		fmt.Println(resp.SecretMessage)
		fmt.Println("═══════════════════════════════════════")

		if resp.IsDecoy {
			fmt.Println("\n⚠ This message was decoded with a decoy key.")
		}
	},
}

var addDecoyKeyCmd = &cobra.Command{
	Use:   "add-decoy-key <session-id> <decoy-message>",
	Short: "Generate a decoy key for a session",
	Long: `Generate a decoy key that can be given to adversaries.

When decrypting with this key, messages will appear as the decoy message
instead of the real content.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := resolveSessionID(args[0])
		decoyMessage := args[1]

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.AddDecoyKey(ctx, &pb.AddDecoyKeyRequest{
			SessionId:    sessionID,
			DecoyMessage: decoyMessage,
		})
		if err != nil {
			exitError("failed to create decoy key", err)
		}

		fmt.Println("Decoy key generated!")
		fmt.Printf("  Key ID:     %s\n", resp.DecoyKeyId)
		fmt.Printf("  Decoy Key:  %s\n", hex.EncodeToString(resp.DecoyKey))
		fmt.Printf("  Decrypts to: %q\n", decoyMessage)
		fmt.Println()
		fmt.Println("⚠ Store this key safely. Give it to adversaries if coerced.")
	},
}

func init() {
	rootCmd.AddCommand(encodeCmd)
	rootCmd.AddCommand(decodeCmd)
	rootCmd.AddCommand(addDecoyKeyCmd)

	encodeCmd.Flags().StringP("decoy", "d", "", "Decoy message for deniable encryption")
	encodeCmd.Flags().StringP("topic", "t", "casual chat", "Topic hint for cover text generation")
	encodeCmd.Flags().Bool("raw", false, "Output only the cover text (for scripting)")
	decodeCmd.Flags().StringP("decoy-key", "k", "", "Decoy key (hex) for deniable decryption")
	decodeCmd.Flags().StringP("topic", "t", "casual chat", "Topic hint used during encoding")
}

// Alias for encode/decode
var sendCmd = &cobra.Command{
	Use:    "send",
	Hidden: true,
}

func init() {
	// Add shorthand aliases
	rootCmd.AddCommand(&cobra.Command{
		Use:   "e",
		Short: "Alias for encode",
		Run:   encodeCmd.Run,
		Args:  encodeCmd.Args,
	})
	rootCmd.AddCommand(&cobra.Command{
		Use:   "d",
		Short: "Alias for decode",
		Run:   decodeCmd.Run,
		Args:  decodeCmd.Args,
	})
}

// Helper for multiline cover text input
func readMultilineInput(prompt string) string {
	fmt.Println(prompt)
	fmt.Println("(enter empty line to finish)")
	var lines []string
	for {
		var line string
		fmt.Scanln(&line)
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
