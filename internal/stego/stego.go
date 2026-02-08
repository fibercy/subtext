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
	"unicode"

	"github.com/cy/stegochat/internal/llm"
)

const (
	// BitsPerDecision is the number of bits encoded per token decision.
	BitsPerDecision = 3
	// NumCandidates is 2^BitsPerDecision
	NumCandidates = 1 << BitsPerDecision
	// MaxSecretLength is the maximum encrypted payload length per segment in bytes
	MaxSecretLength = 256
	// TargetSegmentPayloadLength is the target encrypted payload size per generated cover segment.
	// Smaller segments reduce long-run model drift into meta/instructional text.
	TargetSegmentPayloadLength = 16
	// MaxSegmentEncodeAttempts is the max retries to regenerate a valid segment.
	MaxSegmentEncodeAttempts = 8
)

// segmentSeparator is an explicit boundary between independently decodable cover segments.
const segmentSeparator = "\n\n---SEG---\n\n"

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
	if len(encryptedPayload) == 0 {
		return nil, fmt.Errorf("payload is empty")
	}

	basePrompt := buildPrompt(topic)
	segmentSize := min(TargetSegmentPayloadLength, MaxSecretLength)
	segments := make([]string, 0, (len(encryptedPayload)+segmentSize-1)/segmentSize)
	totalBits := 0
	totalTokens := 0

	for i := 0; i < len(encryptedPayload); i += segmentSize {
		end := min(i+segmentSize, len(encryptedPayload))
		chunk := encryptedPayload[i:end]

		segmentPrompt := buildSegmentPrompt(basePrompt, segments)
		coverSegment, bitsEncoded, tokenCount, err := e.encodeSegment(ctx, segmentPrompt, chunk)
		if err != nil {
			return nil, fmt.Errorf("segment %d encoding failed: %w", len(segments)+1, err)
		}

		segments = append(segments, coverSegment)
		totalBits += bitsEncoded
		totalTokens += tokenCount
	}

	return &EncodeResult{
		CoverText:   strings.Join(segments, segmentSeparator),
		BitsEncoded: totalBits,
		TokenCount:  totalTokens,
	}, nil
}

// EncodeInteractiveSegment encodes one encrypted chunk into one cover segment.
// peerReply is plain text from the peer and is only used as style/context guidance.
func (e *Encoder) EncodeInteractiveSegment(ctx context.Context, encryptedPayload []byte, topic, peerReply string) (*EncodeResult, error) {
	if len(encryptedPayload) == 0 {
		return nil, fmt.Errorf("payload is empty")
	}

	basePrompt := buildPrompt(topic)
	prompt := buildSegmentPromptWithPeerReply(basePrompt, peerReply)

	coverSegment, bitsEncoded, tokenCount, err := e.encodeSegment(ctx, prompt, encryptedPayload)
	if err != nil {
		return nil, err
	}

	return &EncodeResult{
		CoverText:   coverSegment,
		BitsEncoded: bitsEncoded,
		TokenCount:  tokenCount,
	}, nil
}

func (e *Encoder) encodeSegment(ctx context.Context, prompt string, encryptedPayload []byte) (string, int, int, error) {
	if len(encryptedPayload) > MaxSecretLength {
		return "", 0, 0, fmt.Errorf("payload too large: %d bytes (max %d)", len(encryptedPayload), MaxSecretLength)
	}

	// Add a 2-byte length prefix so each segment can be decoded independently.
	payloadWithLen := make([]byte, 2+len(encryptedPayload))
	binary.BigEndian.PutUint16(payloadWithLen[0:2], uint16(len(encryptedPayload)))
	copy(payloadWithLen[2:], encryptedPayload)

	bits := bytesToBits(payloadWithLen)
	for attempt := 1; attempt <= MaxSegmentEncodeAttempts; attempt++ {
		coverText, tokenCount, bitsEncoded, err := e.generateWithBits(ctx, prompt, bits)
		if err != nil {
			if attempt == MaxSegmentEncodeAttempts {
				return "", 0, 0, fmt.Errorf("generation failed: %w", err)
			}
			continue
		}
		if bitsEncoded != len(bits) {
			if attempt == MaxSegmentEncodeAttempts {
				return "", 0, 0, fmt.Errorf("incomplete segment encoding: encoded %d of %d bits", bitsEncoded, len(bits))
			}
			continue
		}
		if !isValidCoverSegment(coverText) {
			if attempt == MaxSegmentEncodeAttempts {
				return "", 0, 0, fmt.Errorf("generated segment failed quality checks")
			}
			continue
		}
		return coverText, len(bits), tokenCount, nil
	}

	return "", 0, 0, fmt.Errorf("segment encoding failed after %d attempts", MaxSegmentEncodeAttempts)
}

// generateWithBits generates text while embedding bits through token selection from logprobs
func (e *Encoder) generateWithBits(ctx context.Context, prompt string, bits []bool) (string, int, int, error) {
	var result strings.Builder
	bitIndex := 0
	tokenCount := 0
	currentPrompt := prompt

	for bitIndex < len(bits) {
		bitsToEncode := min(BitsPerDecision, len(bits)-bitIndex)

		resp, err := e.llmClient.Generate(ctx, currentPrompt, llm.GenerateOptions{
			Temperature: 0.8,
			TopK:        40,
			NumPredict:  1,
			Seed:        promptToSeed(currentPrompt),
		}, true)
		if err != nil {
			return "", 0, 0, fmt.Errorf("generation failed: %w", err)
		}

		logprobItems, err := resp.ParseLogprobs()
		if err != nil {
			return "", 0, 0, fmt.Errorf("failed to parse logprobs: %w", err)
		}

		if len(logprobItems) == 0 || len(logprobItems[0].TopLogprobs) == 0 {
			if resp.Response == "" {
				break
			}
			result.WriteString(resp.Response)
			currentPrompt = prompt + result.String()
			tokenCount++
			continue
		}

		candidates := filterCoverCandidates(logprobItems[0].TopLogprobs)
		numCandidates := len(candidates)

		if numCandidates < (1 << bitsToEncode) {
			for bitsToEncode > 0 && numCandidates < (1<<bitsToEncode) {
				bitsToEncode--
			}
			if bitsToEncode == 0 {
				result.WriteString(candidates[0].Token)
				currentPrompt = prompt + result.String()
				tokenCount++
				continue
			}
		}

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

		if tokenCount > 500 {
			break
		}
	}

	return strings.TrimSpace(result.String()), tokenCount, bitIndex, nil
}

// GenerateReply produces a plain (non-steganographic) conversational reply to a
// received message. The reply respects the topic and conversation context so
// that the overall dialogue reads naturally.
func (e *Encoder) GenerateReply(ctx context.Context, receivedMessage, topic string) (string, error) {
	if topic == "" {
		topic = "casual chat"
	}
	prompt := fmt.Sprintf(`Your friend texted you about %s: "%s"
Reply in 1 short sentence. Casual, lowercase, no quotes, no explanations.
Reply:`, topic, receivedMessage)

	resp, err := e.llmClient.Generate(ctx, prompt, llm.GenerateOptions{
		Temperature: 0.9,
		TopK:        40,
		NumPredict:  40,
		Stop:        []string{"\n", ".", "!"},
	}, false)
	if err != nil {
		return "", fmt.Errorf("reply generation failed: %w", err)
	}

	reply := strings.TrimSpace(resp.Response)
	// Strip any wrapping quotes the LLM might add
	if len(reply) >= 2 && reply[0] == '"' && reply[len(reply)-1] == '"' {
		reply = reply[1 : len(reply)-1]
	}
	// Take only the first line to avoid meta-commentary
	if idx := strings.IndexAny(reply, "\n\r"); idx >= 0 {
		reply = strings.TrimSpace(reply[:idx])
	}
	return reply, nil
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
	return d.DecodeWithPeerReplies(ctx, coverText, topic, nil)
}

// DecodeWithPeerReplies decodes cover segments with optional per-segment peer replies.
// peerReplies maps to segments 2..N (i.e. peerReplies[0] is for segment 2).
func (d *Decoder) DecodeWithPeerReplies(ctx context.Context, coverText string, topic string, peerReplies []string) (*DecodeResult, error) {
	segments := splitCoverSegments(coverText)
	if len(segments) == 0 {
		return &DecodeResult{Valid: false}, nil
	}

	basePrompt := buildPrompt(topic)
	var payload []byte
	totalBits := 0

	for i, segment := range segments {
		segmentPrompt := buildSegmentPrompt(basePrompt, segments[:i])
		if i > 0 && i-1 < len(peerReplies) && strings.TrimSpace(peerReplies[i-1]) != "" {
			segmentPrompt = buildSegmentPromptWithPeerReply(basePrompt, peerReplies[i-1])
		}
		decoded, err := d.decodeSegment(ctx, segment, segmentPrompt)
		if err != nil {
			return nil, fmt.Errorf("segment %d decode failed: %w", i+1, err)
		}
		if !decoded.Valid {
			return &DecodeResult{Valid: false}, nil
		}

		payload = append(payload, decoded.EncryptedPayload...)
		totalBits += decoded.BitsDecoded
	}

	return &DecodeResult{
		EncryptedPayload: payload,
		BitsDecoded:      totalBits,
		Valid:            true,
	}, nil
}

func (d *Decoder) decodeSegment(ctx context.Context, coverText string, prompt string) (*DecodeResult, error) {
	// Extract bits by matching tokens against logprobs at each position
	var extractedBits []bool
	currentPrompt := prompt
	remainingText := coverText
	tokenCount := 0
	// allowTrimmed is true only for the first token, where TrimSpace during
	// encoding may have removed a leading space from the cover text.
	allowTrimmed := true

	for len(remainingText) > 0 {
		// Generate logprobs for current position
		resp, err := d.llmClient.Generate(ctx, currentPrompt, llm.GenerateOptions{
			Temperature: 0.8,
			TopK:        40,
			NumPredict:  1,
			Seed:        promptToSeed(currentPrompt),
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

		candidates := filterCoverCandidates(logprobItems[0].TopLogprobs)
		numCandidates := len(candidates)

		// Determine how many bits were encoded based on candidates
		bitsToExtract := BitsPerDecision
		for bitsToExtract > 0 && numCandidates < (1<<bitsToExtract) {
			bitsToExtract--
		}

		// Find which candidate token matches the start of remainingText.
		// With prefix-free candidates, the first match is unambiguous.
		matchIndex := -1
		matchedToken := ""
		actualConsumed := ""
		for i, cand := range candidates {
			if i >= (1 << bitsToExtract) {
				break
			}
			token := cand.Token
			if strings.HasPrefix(remainingText, token) {
				matchIndex = i
				matchedToken = token
				actualConsumed = token
				break
			}
			// Trimmed match only for the very first token (handles TrimSpace)
			if allowTrimmed {
				trimmedToken := strings.TrimLeft(token, " ")
				if trimmedToken != token && trimmedToken != "" && strings.HasPrefix(remainingText, trimmedToken) {
					matchIndex = i
					matchedToken = token
					actualConsumed = trimmedToken
					break
				}
			}
		}

		if matchIndex < 0 {
			// No match in encoding range — try any candidate to advance
			for _, cand := range candidates {
				if strings.HasPrefix(remainingText, cand.Token) {
					matchedToken = cand.Token
					actualConsumed = cand.Token
					break
				}
			}
			if actualConsumed == "" {
				// Skip one character and try again
				if len(remainingText) > 0 {
					remainingText = remainingText[1:]
					continue
				}
				break
			}
		} else if bitsToExtract > 0 {
			bits := intToBits(matchIndex, bitsToExtract)
			extractedBits = append(extractedBits, bits...)
		}

		// After first successful match, disable trimmed matching
		allowTrimmed = false

		// Advance past matched token
		if actualConsumed != "" {
			remainingText = strings.TrimPrefix(remainingText, actualConsumed)
			currentPrompt = currentPrompt + matchedToken // Use original token for prompt
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
	return fmt.Sprintf(`Write one natural everyday text message about %s.
Hard rules:
- 1 to 2 short sentences only
- 12 to 28 words total
- plain conversational English, mostly lowercase
- mundane and specific (like normal daily life)
- no bullets, no lists, no quotes
- no brackets or parentheses
- no explanations about style or generation
- output only the message text
	`, topic)
}

func buildSegmentPrompt(basePrompt string, previousSegments []string) string {
	if len(previousSegments) == 0 {
		return basePrompt
	}

	previous := strings.TrimSpace(previousSegments[len(previousSegments)-1])
	const maxPreviousChars = 220
	if len(previous) > maxPreviousChars {
		previous = previous[len(previous)-maxPreviousChars:]
	}

	return fmt.Sprintf(`%s
Continue the same chat thread from the same person.
Keep continuity with details and tone from the previous message.
Previous message:
%s
Next message:
`, basePrompt, previous)
}

func buildSegmentPromptWithPeerReply(basePrompt, peerReply string) string {
	peerReply = strings.TrimSpace(peerReply)
	if peerReply == "" {
		return basePrompt
	}
	const maxReplyChars = 220
	if len(peerReply) > maxReplyChars {
		peerReply = peerReply[len(peerReply)-maxReplyChars:]
	}

	return fmt.Sprintf(`%s
Continue the same chat thread from the same person.
Adapt naturally to the peer's latest reply while staying mundane.
Peer reply:
%s
Next message:
`, basePrompt, peerReply)
}

func filterCoverCandidates(candidates []llm.LogprobToken) []llm.LogprobToken {
	filtered := make([]llm.LogprobToken, 0, len(candidates))
	for _, cand := range candidates {
		if isAllowedCoverToken(cand.Token) {
			filtered = append(filtered, cand)
		}
	}
	if len(filtered) == 0 {
		return candidates
	}
	return makePrefixFree(filtered)
}

// makePrefixFree removes candidates whose token is a prefix of (or has a prefix in)
// an already-accepted candidate. This ensures unambiguous token matching during decode.
// Candidates are processed in logprob order (most probable first) so higher-probability
// tokens are preferred.
func makePrefixFree(candidates []llm.LogprobToken) []llm.LogprobToken {
	result := make([]llm.LogprobToken, 0, len(candidates))
	for _, c := range candidates {
		conflict := false
		for _, r := range result {
			if strings.HasPrefix(c.Token, r.Token) || strings.HasPrefix(r.Token, c.Token) {
				conflict = true
				break
			}
		}
		if !conflict {
			result = append(result, c)
		}
	}
	if len(result) == 0 {
		return candidates
	}
	return result
}

func isAllowedCoverToken(token string) bool {
	if token == "" {
		return false
	}
	if strings.ContainsAny(token, "\n\r\t[]{}<>") {
		return false
	}
	if containsInvisible(token) {
		return false
	}

	trimmed := strings.ToLower(strings.TrimSpace(token))
	badToken := map[string]struct{}{
		"note":         {},
		"instruction":  {},
		"instructions": {},
		"prompt":       {},
		"rules":        {},
	}
	if _, found := badToken[trimmed]; found {
		return false
	}
	if strings.HasPrefix(trimmed, "write") {
		return false
	}

	return true
}

// containsInvisible returns true if s contains any zero-width or invisible
// Unicode characters that cause decode mismatches.
func containsInvisible(s string) bool {
	for _, r := range s {
		if isInvisibleRune(r) {
			return true
		}
	}
	return false
}

func isInvisibleRune(r rune) bool {
	// Zero-width and formatting characters
	switch r {
	case '\u200B', // zero-width space
		'\u200C', // zero-width non-joiner
		'\u200D', // zero-width joiner
		'\u200E', // left-to-right mark
		'\u200F', // right-to-left mark
		'\uFEFF', // BOM / zero-width no-break space
		'\u2060', // word joiner
		'\u2061', // function application
		'\u2062', // invisible times
		'\u2063', // invisible separator
		'\u2064', // invisible plus
		'\u00AD': // soft hyphen
		return true
	}
	// Catch remaining Cf (format) category chars
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	return false
}

func splitCoverSegments(coverText string) []string {
	coverText = strings.TrimSpace(coverText)
	if coverText == "" {
		return nil
	}

	parts := strings.Split(coverText, segmentSeparator)
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			segments = append(segments, part)
		}
	}
	return segments
}

// JoinCoverSegments joins independently encoded cover segments into one decode-able payload.
func JoinCoverSegments(segments []string) string {
	clean := make([]string, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment != "" {
			clean = append(clean, segment)
		}
	}
	return strings.Join(clean, segmentSeparator)
}

func isValidCoverSegment(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	if strings.Contains(text, segmentSeparator) {
		return false
	}
	if strings.Contains(text, "\n") || strings.Contains(text, "\r") {
		return false
	}
	if strings.ContainsAny(text, "[]{}<>") {
		return false
	}
	if containsInvisible(text) {
		return false
	}

	words := strings.Fields(text)
	if len(words) < 8 || len(words) > 90 {
		return false
	}

	lower := strings.ToLower(text)
	badPhrases := []string{
		"write one sentence",
		"write a sentence",
		"hard rules",
		"output only",
		"this text",
		"no changes in punctuation",
		"optional argumentation",
		"include names",
		"instruction",
		"prompt",
	}
	for _, phrase := range badPhrases {
		if strings.Contains(lower, phrase) {
			return false
		}
	}

	return true
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

// promptToSeed generates a deterministic seed from a prompt for reproducible LLM output
func promptToSeed(prompt string) int {
	h := fnv.New32a()
	h.Write([]byte(prompt))
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
