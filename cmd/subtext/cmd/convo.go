package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/cy/subtext/internal/subtext"
	pb "github.com/cy/subtext/proto"
	"github.com/spf13/cobra"
)

var convoCmd = &cobra.Command{
	Use:   "convo",
	Short: "Interactive segmented messaging workflow",
	Long: `Interactive segmented messaging:
1) sender starts a flow and gets the first cover segment
2) sender waits for peer's normal plaintext reply
3) sender requests next segment using that reply as context
4) receiver collects all cover segments and decodes once`,
}

var convoStartCmd = &cobra.Command{
	Use:   "start <session-id> <secret-message>",
	Short: "Start interactive segmented encoding and return the first segment",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := resolveSessionID(args[0])
		secretMessage := args[1]
		topicHint, _ := cmd.Flags().GetString("topic")

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.StartInteractiveEncode(ctx, &pb.StartInteractiveEncodeRequest{
			SessionId:     sessionID,
			SecretMessage: secretMessage,
			TopicHint:     topicHint,
		})
		if err != nil {
			exitError("failed to start interactive encoding", err)
		}

		raw, _ := cmd.Flags().GetBool("raw")
		if raw {
			// Machine-parseable: flow_id<TAB>cover_text<TAB>done<TAB>attempt
			done := "0"
			if resp.Done {
				done = "1"
			}
			fmt.Printf("%s\t%s\t%s\t%d", resp.FlowId, resp.CoverText, done, resp.EncodeAttempt)
			return
		}

		fmt.Printf("Flow ID: %s\n", resp.FlowId)
		fmt.Printf("Segment: %d/%d\n\n", resp.SegmentIndex, resp.TotalSegments)
		fmt.Println(resp.CoverText)
		if resp.Done {
			fmt.Println("\nAll segments generated in this step.")
		} else {
			fmt.Println("\nSend this segment, wait for peer reply, then run:")
			fmt.Printf("  stego convo next %s \"<peer-reply>\"\n", resp.FlowId)
		}
	},
}

var convoNextCmd = &cobra.Command{
	Use:   "next <flow-id> <peer-reply>",
	Short: "Generate the next segment after receiving a normal peer reply",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		flowID := args[0]
		peerReply := args[1]

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.ContinueInteractiveEncode(ctx, &pb.ContinueInteractiveEncodeRequest{
			FlowId:    flowID,
			PeerReply: peerReply,
		})
		if err != nil {
			exitError("failed to continue interactive encoding", err)
		}

		raw, _ := cmd.Flags().GetBool("raw")
		if raw {
			// Machine-parseable: flow_id<TAB>cover_text<TAB>done<TAB>attempt
			done := "0"
			if resp.Done {
				done = "1"
			}
			fmt.Printf("%s\t%s\t%s\t%d", resp.FlowId, resp.CoverText, done, resp.EncodeAttempt)
			return
		}

		fmt.Printf("Flow ID: %s\n", resp.FlowId)
		fmt.Printf("Segment: %d/%d\n\n", resp.SegmentIndex, resp.TotalSegments)
		fmt.Println(resp.CoverText)
		if resp.Done {
			fmt.Println("\nFlow complete. Receiver can now decode all collected segments together.")
		}
	},
}

var convoDecodeCmd = &cobra.Command{
	Use:   "decode <session-id>",
	Short: "Decode a full interactive flow after collecting all cover segments",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sessionID := resolveSessionID(args[0])
		covers, _ := cmd.Flags().GetStringArray("cover")
		coverFile, _ := cmd.Flags().GetString("cover-file")
		peerReplies, _ := cmd.Flags().GetStringArray("peer-reply")
		topicHint, _ := cmd.Flags().GetString("topic")
		attemptStrs, _ := cmd.Flags().GetStringArray("attempt")

		var coverText string
		switch {
		case len(covers) > 0:
			coverText = subtext.JoinCoverSegments(covers)
		case coverFile != "":
			data, err := os.ReadFile(coverFile)
			if err != nil {
				exitError("failed to read cover file", err)
			}
			coverText = string(data)
		default:
			exitError("missing input", fmt.Errorf("provide at least one --cover or --cover-file"))
		}

		// Convert attempt strings to int32 slice
		var encodeAttempts []int32
		for _, s := range attemptStrs {
			a, err := strconv.Atoi(s)
			if err != nil {
				exitError("invalid attempt number", err)
			}
			encodeAttempts = append(encodeAttempts, int32(a))
		}

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.DecodeMessage(ctx, &pb.DecodeMessageRequest{
			SessionId:      sessionID,
			CoverText:      coverText,
			PeerReplies:    peerReplies,
			TopicHint:      topicHint,
			EncodeAttempts: encodeAttempts,
		})
		if err != nil {
			exitError("decoding failed", err)
		}

		fmt.Println(resp.SecretMessage)
	},
}

func init() {
	rootCmd.AddCommand(convoCmd)
	convoCmd.AddCommand(convoStartCmd)
	convoCmd.AddCommand(convoNextCmd)
	convoCmd.AddCommand(convoDecodeCmd)

	convoStartCmd.Flags().StringP("topic", "t", "casual chat", "Topic hint for cover text generation")
	convoStartCmd.Flags().Bool("raw", false, "Output only the cover text")
	convoNextCmd.Flags().Bool("raw", false, "Output only the cover text")
	convoDecodeCmd.Flags().StringArray("cover", nil, "Collected cover segment (repeat for multiple)")
	convoDecodeCmd.Flags().String("cover-file", "", "File containing full assembled cover text")
	convoDecodeCmd.Flags().StringArray("peer-reply", nil, "Peer plaintext reply for each transition (repeat in order for segment2..N)")
	convoDecodeCmd.Flags().StringP("topic", "t", "casual chat", "Topic hint used during encoding")
	convoDecodeCmd.Flags().StringArray("attempt", nil, "Per-segment encoder attempt number (repeat for each segment, 1-based)")
}
