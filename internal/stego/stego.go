// Package stego implements steganographic encoding/decoding using LLM-based text generation.
package stego

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"strings"

	"github.com/cy/stegochat/internal/llm"
)

const (
	// BitsPerDecision is the number of bits encoded per token decision
	BitsPerDecision = 4
	// NumCandidates is 2^BitsPerDecision
	NumCandidates = 1 << BitsPerDecision
	// MaxSecretLength is the maximum secret message length in bytes
	MaxSecretLength = 64
)

// Encoder handles steganographic encoding of messages into cover text
type Encoder struct {
	llmClient *llm.Client
}

// NewEncoder creates a new steganographic encoder
func NewEncoder(client *llm.Client) *Encoder {
	return &Encoder{llmClient: client}
}

// EncodeResult contains the encoding output
type EncodeResult struct {
	CoverText   string
	BitsEncoded int
	TokenCount  int
}

// Encode encodes an encrypted payload into cover text
func (e *Encoder) Encode(ctx context.Context, encryptedPayload []byte, topic string) (*EncodeResult, error) {
	if len(encryptedPayload) > MaxSecretLength {
		return nil, fmt.Errorf("payload too large: %d bytes (max %d)", len(encryptedPayload), MaxSecretLength)
	}

	// Encode the encrypted payload directly (compact crypto has built-in integrity)
	// Add length prefix for decoding (2 bytes)
	payloadWithLen := make([]byte, 2+len(encryptedPayload))
	binary.BigEndian.PutUint16(payloadWithLen[0:2], uint16(len(encryptedPayload)))
	copy(payloadWithLen[2:], encryptedPayload)

	bits := bytesToBits(payloadWithLen)

	// Build the prompt for cover text generation
	prompt := buildPrompt(topic)

	// Generate cover text with embedded bits
	coverText, tokenCount, err := e.generateWithBits(ctx, prompt, bits)
	if err != nil {
		return nil, fmt.Errorf("generation failed: %w", err)
	}

	return &EncodeResult{
		CoverText:   coverText,
		BitsEncoded: len(bits),
		TokenCount:  tokenCount,
	}, nil
}

// generateWithBits generates text while embedding bits through token selection from logprobs
func (e *Encoder) generateWithBits(ctx context.Context, prompt string, bits []bool) (string, int, error) {
	// Optimized approach using logprobs:
	// 1. Generate one token with logprobs enabled
	// 2. Select token from top_logprobs based on bit value
	// 3. Append to result and continue

	var result strings.Builder
	bitIndex := 0
	tokenCount := 0
	currentPrompt := prompt

	for bitIndex < len(bits) {
		// Determine how many bits we can encode (limited by available candidates)
		bitsToEncode := min(BitsPerDecision, len(bits)-bitIndex)

		// Single LLM call with logprobs
		resp, err := e.llmClient.Generate(ctx, currentPrompt, llm.GenerateOptions{
			Temperature: 0.8,
			TopK:        40,
			NumPredict:  1, // Generate exactly 1 token
		}, true) // logprobs=true
		if err != nil {
			return "", 0, fmt.Errorf("generation failed: %w", err)
		}

		// Parse logprobs
		logprobItems, err := resp.ParseLogprobs()
		if err != nil {
			return "", 0, fmt.Errorf("failed to parse logprobs: %w", err)
		}

		if len(logprobItems) == 0 || len(logprobItems[0].TopLogprobs) == 0 {
			// Fallback to default response if no logprobs
			if resp.Response == "" {
				break
			}
			result.WriteString(resp.Response)
			currentPrompt = prompt + result.String()
			tokenCount++
			continue
		}

		// Get available candidates from top_logprobs
		candidates := logprobItems[0].TopLogprobs
		numCandidates := len(candidates)

		// Adjust bits if not enough candidates
		if numCandidates < (1 << bitsToEncode) {
			// Reduce bits per decision if not enough candidates
			for bitsToEncode > 0 && numCandidates < (1<<bitsToEncode) {
				bitsToEncode--
			}
			if bitsToEncode == 0 {
				// Use the top candidate, encode 0 bits
				result.WriteString(candidates[0].Token)
				currentPrompt = prompt + result.String()
				tokenCount++
				continue
			}
		}

		// Calculate bit value and select token
		bitValue := bitsToInt(bits[bitIndex : bitIndex+bitsToEncode])
		selectedIndex := bitValue % (1 << bitsToEncode)
		if selectedIndex >= numCandidates {
			selectedIndex = 0
		}

		selectedToken := candidates[selectedIndex].Token
		result.WriteString(selectedToken)
		currentPrompt = prompt + result.String()
		tokenCount++
		bitIndex += bitsToEncode

		// Safety limit
		if tokenCount > 500 {
			break
		}
	}

	return strings.TrimSpace(result.String()), tokenCount, nil
}

// Decoder handles steganographic decoding of messages from cover text
type Decoder struct {
	llmClient *llm.Client
}

// NewDecoder creates a new steganographic decoder
func NewDecoder(client *llm.Client) *Decoder {
	return &Decoder{llmClient: client}
}

// DecodeResult contains the decoding output
type DecodeResult struct {
	EncryptedPayload []byte
	BitsDecoded      int
	Valid            bool
}

// Decode extracts the encrypted payload from cover text
func (d *Decoder) Decode(ctx context.Context, coverText string, topic string) (*DecodeResult, error) {
	prompt := buildPrompt(topic)

	// Extract bits by matching tokens against logprobs at each position
	var extractedBits []bool
	currentPrompt := prompt
	remainingText := coverText
	tokenCount := 0

	for len(remainingText) > 0 {
		// Generate logprobs for current position
		resp, err := d.llmClient.Generate(ctx, currentPrompt, llm.GenerateOptions{
			Temperature: 0.8,
			TopK:        40,
			NumPredict:  1,
		}, true)
		if err != nil {
			return nil, fmt.Errorf("logprobs generation failed: %w", err)
		}

		logprobItems, err := resp.ParseLogprobs()
		if err != nil {
			return nil, fmt.Errorf("failed to parse logprobs: %w", err)
		}

		if len(logprobItems) == 0 || len(logprobItems[0].TopLogprobs) == 0 {
			// Cannot decode without logprobs
			break
		}

		candidates := logprobItems[0].TopLogprobs
		numCandidates := len(candidates)

		// Determine how many bits were encoded based on candidates
		bitsToExtract := BitsPerDecision
		for bitsToExtract > 0 && numCandidates < (1<<bitsToExtract) {
			bitsToExtract--
		}

		// Find which candidate token matches the start of remainingText
		matchIndex := -1
		matchedToken := ""
		for i, cand := range candidates {
			if i >= (1 << bitsToExtract) {
				break // Only check candidates within encoding range
			}
			if strings.HasPrefix(remainingText, cand.Token) {
				// Prefer longest match for ambiguity resolution
				if len(cand.Token) > len(matchedToken) {
					matchIndex = i
					matchedToken = cand.Token
				}
			}
		}

		if matchIndex < 0 {
			// No match found - try to find any matching token to continue
			for _, cand := range candidates {
				if strings.HasPrefix(remainingText, cand.Token) {
					matchedToken = cand.Token
					break
				}
			}
			if matchedToken == "" {
				// Skip one character and try again
				if len(remainingText) > 0 {
					remainingText = remainingText[1:]
					continue
				}
				break
			}
			// Found token but not in encoding range, skip without extracting bits
		} else if bitsToExtract > 0 {
			// Extract bits from match index
			bits := intToBits(matchIndex, bitsToExtract)
			extractedBits = append(extractedBits, bits...)
		}

		// Advance past matched token
		if matchedToken != "" {
			remainingText = strings.TrimPrefix(remainingText, matchedToken)
			currentPrompt = currentPrompt + matchedToken
		}
		tokenCount++

		// Safety limits
		if tokenCount > 500 || len(extractedBits) > (MaxSecretLength+2)*8+100 {
			break
		}
	}

	// Convert bits back to bytes
	extractedBytes := bitsToBytes(extractedBits)
	if len(extractedBytes) < 2 {
		return &DecodeResult{Valid: false}, nil
	}

	// Parse length prefix
	payloadLen := int(binary.BigEndian.Uint16(extractedBytes[0:2]))

	if payloadLen > len(extractedBytes)-2 || payloadLen > MaxSecretLength {
		return &DecodeResult{Valid: false}, nil
	}

	payload := extractedBytes[2 : 2+payloadLen]

	// Validity is determined by successful decryption (compact crypto has integrity check)
	return &DecodeResult{
		EncryptedPayload: payload,
		BitsDecoded:      len(extractedBits),
		Valid:            true,
	}, nil
}

// Helper functions

func buildPrompt(topic string) string {
	if topic == "" {
		topic = "your day"
	}

	// Try to load prompt from file for easy tuning
	promptFile := "internal/stego/prompt.txt"
	if data, err := os.ReadFile(promptFile); err == nil {
		return strings.ReplaceAll(string(data), "{{TOPIC}}", topic)
	}

	// Fallback to embedded prompt
	return fmt.Sprintf(`Write a casual chat message about %s. Be natural and friendly, like texting a friend. Just write the message content, no labels or formatting:

`, topic)
}

func extractChunk(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}

	// Find the first word or punctuation group
	end := 0
	inWord := false
	for i, r := range text {
		if r == ' ' || r == '\n' || r == '\t' {
			if inWord {
				end = i
				break
			}
		} else {
			inWord = true
			end = i + 1
		}
	}

	if end == 0 {
		end = len(text)
	}

	chunk := text[:end]
	if len(chunk) > 0 && chunk[len(chunk)-1] != ' ' {
		chunk += " "
	}
	return chunk
}

func getSeed(prompt string, variant int) int {
	h := fnv.New32a()
	h.Write([]byte(prompt))
	h.Write([]byte{byte(variant)})
	return int(h.Sum32())
}

func computeChecksum(data []byte) uint16 {
	h := fnv.New32a()
	h.Write(data)
	return uint16(h.Sum32() & 0xFFFF)
}

func bytesToBits(data []byte) []bool {
	bits := make([]bool, len(data)*8)
	for i, b := range data {
		for j := 0; j < 8; j++ {
			bits[i*8+j] = (b>>(7-j))&1 == 1
		}
	}
	return bits
}

func bitsToBytes(bits []bool) []byte {
	numBytes := len(bits) / 8
	bytes := make([]byte, numBytes)
	for i := 0; i < numBytes; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			if bits[i*8+j] {
				b |= 1 << (7 - j)
			}
		}
		bytes[i] = b
	}
	return bytes
}

func bitsToInt(bits []bool) int {
	result := 0
	for _, b := range bits {
		result <<= 1
		if b {
			result |= 1
		}
	}
	return result
}

func intToBits(n, numBits int) []bool {
	bits := make([]bool, numBits)
	for i := numBits - 1; i >= 0; i-- {
		bits[numBits-1-i] = (n>>i)&1 == 1
	}
	return bits
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GenerateRandomBytes generates cryptographically random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
