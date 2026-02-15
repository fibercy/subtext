package cmd

import (
	"fmt"

	pb "github.com/cy/subtext/proto"
	"github.com/spf13/cobra"
)

var replyCmd = &cobra.Command{
	Use:   "reply <message>",
	Short: "Generate a natural peer reply to a received message (no hidden data)",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		message := args[0]
		topicHint, _ := cmd.Flags().GetString("topic")

		ctx, cancel := getContext()
		defer cancel()

		resp, err := client.GeneratePeerReply(ctx, &pb.GeneratePeerReplyRequest{
			Message:   message,
			TopicHint: topicHint,
		})
		if err != nil {
			exitError("failed to generate reply", err)
		}

		raw, _ := cmd.Flags().GetBool("raw")
		if raw {
			fmt.Print(resp.Reply)
			return
		}

		fmt.Println(resp.Reply)
	},
}

func init() {
	rootCmd.AddCommand(replyCmd)
	replyCmd.Flags().StringP("topic", "t", "casual chat", "Topic hint for contextual reply")
	replyCmd.Flags().Bool("raw", false, "Output only the reply text")
}
