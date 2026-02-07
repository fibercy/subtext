// Package stego implements steganographic encoding/decoding using LLM-based text generation.
package stego

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/cy/stegochat/internal/llm"
)

const (
	// BitsPerDecision is the number of bits encoded per token decision
	BitsPerDecision = 2
	// NumCandidates is 2^BitsPerDecision
	NumCandidates = 1 << BitsPerDecision
	// MaxSecretLength is the maximum secret message length in bytes
	MaxSecretLength = 64
	// HeaderSize is the size of the embedded header (length + checksum)
	HeaderSize = 4
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

	// Prepare payload with header: [length (2 bytes)] [checksum (2 bytes)] [data]
	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encryptedPayload)))
	checksum := computeChecksum(encryptedPayload)
	binary.BigEndian.PutUint16(header[2:4], checksum)

	fullPayload := append(header, encryptedPayload...)
	bits := bytesToBits(fullPayload)

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

// generateWithBits generates text while embedding bits through word choice
func (e *Encoder) generateWithBits(ctx context.Context, prompt string, bits []bool) (string, int, error) {
	// For this implementation, we use a deterministic approach:
	// 1. Generate multiple candidate responses
	// 2. Hash each candidate and use bits to select which one to keep
	// 3. Continue building the response piece by piece

	var result strings.Builder
	bitIndex := 0
	tokenCount := 0

	// We'll generate the text in chunks, using bits to influence word choice
	currentPrompt := prompt

	for bitIndex < len(bits) {
		// Determine how many bits we can encode in this chunk
		bitsToEncode := min(BitsPerDecision, len(bits)-bitIndex)
		bitValue := bitsToInt(bits[bitIndex : bitIndex+bitsToEncode])

		// Generate candidates with different seeds
		candidates := make([]string, NumCandidates)
		for i := 0; i < NumCandidates; i++ {
			resp, err := e.llmClient.Generate(ctx, currentPrompt, llm.GenerateOptions{
				Temperature: 0.8,
				TopK:        40,
				NumPredict:  10, // Generate short chunks
				Seed:        getSeed(currentPrompt, i),
			}, false)
			if err != nil {
				return "", 0, fmt.Errorf("candidate %d generation failed: %w", i, err)
			}
			candidates[i] = resp.Response
		}

		// Select candidate based on bit value
		selectedCandidate := candidates[bitValue%len(candidates)]

		// Extract first "word" or meaningful chunk from the selected candidate
		chunk := extractChunk(selectedCandidate)
		if chunk == "" {
			// If we can't get a chunk, just use the first candidate
			chunk = extractChunk(candidates[0])
			if chunk == "" {
				break // Can't generate more text
			}
		}

		result.WriteString(chunk)
		currentPrompt = prompt + result.String()
		tokenCount++
		bitIndex += bitsToEncode

		// Safety limit
		if tokenCount > 200 {
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

	// Reconstruct bits by determining which candidate was chosen at each step
	var extractedBits []bool
	currentPrompt := prompt
	remainingText := coverText

	for len(remainingText) > 0 {
		// Find the next chunk in the cover text
		chunk := extractChunk(remainingText)
		if chunk == "" {
			break
		}

		// Generate candidates with the same seeds as encoding
		candidates := make([]string, NumCandidates)
		for i := 0; i < NumCandidates; i++ {
			resp, err := d.llmClient.Generate(ctx, currentPrompt, llm.GenerateOptions{
				Temperature: 0.8,
				TopK:        40,
				NumPredict:  10,
				Seed:        getSeed(currentPrompt, i),
			}, false)
			if err != nil {
				return nil, fmt.Errorf("candidate %d generation failed: %w", i, err)
			}
			candidates[i] = resp.Response
		}

		// Find which candidate matches the actual chunk
		matchIndex := -1
		for i, cand := range candidates {
			candChunk := extractChunk(cand)
			if candChunk == chunk {
				matchIndex = i
				break
			}
		}

		if matchIndex >= 0 {
			// Extract bits from the match index
			bits := intToBits(matchIndex, BitsPerDecision)
			extractedBits = append(extractedBits, bits...)
		}

		// Move forward in the text
		remainingText = strings.TrimPrefix(remainingText, chunk)
		remainingText = strings.TrimSpace(remainingText)
		currentPrompt = prompt + strings.TrimSuffix(coverText, remainingText)

		// Safety limit
		if len(extractedBits) > (MaxSecretLength+HeaderSize)*8+100 {
			break
		}
	}

	// Convert bits back to bytes
	extractedBytes := bitsToBytes(extractedBits)
	if len(extractedBytes) < HeaderSize {
		return &DecodeResult{Valid: false}, nil
	}

	// Parse header
	payloadLen := int(binary.BigEndian.Uint16(extractedBytes[0:2]))
	expectedChecksum := binary.BigEndian.Uint16(extractedBytes[2:4])

	if payloadLen > len(extractedBytes)-HeaderSize {
		return &DecodeResult{Valid: false}, nil
	}

	payload := extractedBytes[HeaderSize : HeaderSize+payloadLen]
	actualChecksum := computeChecksum(payload)

	return &DecodeResult{
		EncryptedPayload: payload,
		BitsDecoded:      len(extractedBits),
		Valid:            expectedChecksum == actualChecksum,
	}, nil
}

// Helper functions

func buildPrompt(topic string) string {
	if topic == "" {
		topic = "casual conversation"
	}
	return fmt.Sprintf(`Continue this friendly conversation about %s. Write naturally and casually:

Person A: Hey, what's up?
Person B: Not much, just relaxing. 
Person A: Nice! `, topic)
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
