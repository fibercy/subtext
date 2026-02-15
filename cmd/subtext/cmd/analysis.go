package cmd

import (
	"fmt"
	"os"

	"github.com/cy/subtext/internal/analysis"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze <text OR file>",
	Short: "Analyze text for steganography detection risk",
	Long: `Analyze text to detect potential steganographic signatures.
Calculates statistical metrics including entropy, character frequency,
and naturalness scores.

Arguments can be direct text or a path to a file.

Example:
  stego analyze "Some text to analyze"
  stego analyze message.txt`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := args[0]
		var text string

		// Check if input is a file
		if _, err := os.Stat(input); err == nil {
			content, err := os.ReadFile(input)
			if err != nil {
				exitError("failed to read file", err)
			}
			text = string(content)
			fmt.Printf("Analyzing file: %s (%d bytes)\n", input, len(text))
		} else {
			text = input
			fmt.Println("Analyzing input text...")
		}

		fmt.Println("───────────────────────────────────────")

		stats := analysis.AnalyzeText(text)
		risk := analysis.DetectionRisk(text)

		fmt.Printf("Basic Metrics:\n")
		fmt.Printf("  Words:        %d\n", stats.WordCount)
		fmt.Printf("  Avg Word Len: %.2f chars\n", stats.AvgWordLength)
		fmt.Printf("  Sentences:    %d\n", stats.SentenceCount)

		fmt.Printf("\nStatistical Indicators:\n")
		fmt.Printf("  Char Entropy: %.2f bits/char (Normal: ~4.0-4.5)\n", stats.CharEntropy)
		fmt.Printf("  Word Entropy: %.2f bits/word\n", stats.WordEntropy)
		fmt.Printf("  Punctuation:  %.1f%%\n", stats.PunctuationRatio*100)
		fmt.Printf("  Repetition:   %.2f (Lower is better)\n", stats.RepetitionScore)

		fmt.Printf("\nScores:\n")
		fmt.Printf("  English Sim:  %.2f / 1.0\n", analysis.CompareToEnglish(stats))
		fmt.Printf("  Naturalness:  %.2f / 1.0\n", analysis.NaturalnessScore(stats))

		fmt.Println("───────────────────────────────────────")
		fmt.Printf("DETECTION RISK: ")

		switch {
		case risk < 0.3:
			fmt.Printf("LOW (%.2f)\n", risk)
			fmt.Println("✓ This text looks natural and safe.")
		case risk < 0.6:
			fmt.Printf("MEDIUM (%.2f)\n", risk)
			fmt.Println("⚠ Some statistical anomalies detected.")
		default:
			fmt.Printf("HIGH (%.2f)\n", risk)
			fmt.Println("✗ This text looks artificial/suspicious.")
		}
	},
}

func init() {
	rootCmd.AddCommand(analyzeCmd)
}
