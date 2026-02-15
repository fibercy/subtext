// Package subtext implements steganographic encoding/decoding using LLM-based text generation.
package subtext

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"unicode"

	"github.com/cy/subtext/internal/llm"
)

const (
	// BitsPerDecision is the number of bits encoded per token decision.
	// With token-hash encoding and ~10-15 filtered candidates, ~78% of
	// positions encode 2 bits, the rest fall back to 1 → avg ~1.5 bits/token.
	BitsPerDecision = 2
	// MaxSecretLength is the maximum encrypted payload length per segment in bytes
	MaxSecretLength = 256
	// TargetSegmentPayloadLength is the target encrypted payload size per generated cover segment.
	// At ~1.5 bits/token avg: 4 payload + 2 length prefix = 6 bytes = 48 bits ≈ 27 tokens.
	// Proven reliable: keeps each segment within the model's coherent generation range.
	TargetSegmentPayloadLength = 4
	// MaxSegmentEncodeAttempts is the max retries to regenerate a valid segment.
	MaxSegmentEncodeAttempts = 12
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
	Attempt     int // 1-based retry attempt that succeeded (decoder needs this to match prompt variation)
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
		coverSegment, bitsEncoded, tokenCount, _, err := e.encodeSegment(ctx, segmentPrompt, chunk)
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

	coverSegment, bitsEncoded, tokenCount, attempt, err := e.encodeSegment(ctx, prompt, encryptedPayload)
	if err != nil {
		return nil, err
	}

	return &EncodeResult{
		CoverText:   coverSegment,
		BitsEncoded: bitsEncoded,
		TokenCount:  tokenCount,
		Attempt:     attempt,
	}, nil
}

// encodeSegment returns (coverText, bitsEncoded, tokenCount, attempt, error).
// attempt is the 1-based retry number that succeeded (used by decoder to match prompt variation).
func (e *Encoder) encodeSegment(ctx context.Context, prompt string, encryptedPayload []byte) (string, int, int, int, error) {
	if len(encryptedPayload) > MaxSecretLength {
		return "", 0, 0, 0, fmt.Errorf("payload too large: %d bytes (max %d)", len(encryptedPayload), MaxSecretLength)
	}

	// Add a 2-byte length prefix so each segment can be decoded independently.
	payloadWithLen := make([]byte, 2+len(encryptedPayload))
	binary.BigEndian.PutUint16(payloadWithLen[0:2], uint16(len(encryptedPayload)))
	copy(payloadWithLen[2:], encryptedPayload)

	bits := bytesToBits(payloadWithLen)
	// Pad to a multiple of BitsPerDecision so the encoder always uses the full
	// bit width. Without this, the last token might encode fewer bits than the
	// decoder extracts (the decoder can't know the total count), causing a
	// bit-stream shift that corrupts the payload.
	for len(bits)%BitsPerDecision != 0 {
		bits = append(bits, false)
	}
	for attempt := 1; attempt <= MaxSegmentEncodeAttempts; attempt++ {
		attemptPrompt := prompt + promptVariation(attempt)
		coverText, tokenCount, bitsEncoded, err := e.generateWithBits(ctx, attemptPrompt, bits)
		if err != nil {
			if attempt == MaxSegmentEncodeAttempts {
				return "", 0, 0, 0, fmt.Errorf("generation failed: %w", err)
			}
			continue
		}
		if bitsEncoded != len(bits) {
			if attempt == MaxSegmentEncodeAttempts {
				return "", 0, 0, 0, fmt.Errorf("incomplete segment encoding: encoded %d of %d bits", bitsEncoded, len(bits))
			}
			continue
		}
		if !isValidCoverSegment(coverText) {
			if attempt == MaxSegmentEncodeAttempts {
				return "", 0, 0, 0, fmt.Errorf("generated segment failed quality checks")
			}
			continue
		}
		return coverText, len(bits), tokenCount, attempt, nil
	}

	return "", 0, 0, 0, fmt.Errorf("segment encoding failed after %d attempts", MaxSegmentEncodeAttempts)
}

// formatPrompt builds the full prompt for stego encoding/decoding.
// Uses the ChatML template when available so Qwen can distinguish the
// instruction from the expected assistant output.
func (e *Encoder) formatPrompt(instruction, assistantText string) string {
	tmpl := e.llmClient.GetChatTemplate()
	if tmpl != nil {
		return tmpl.FormatPrompt(instruction, assistantText)
	}
	return instruction + assistantText
}

// eosMarkers are continuation tokens inserted when the model hits EOS mid-encoding.
// Both encoder and decoder detect EOS at the same position (same prompt → same logprobs)
// and agree to insert/skip this marker without encoding/extracting bits.
// Multiple markers are rotated to prevent the model from getting stuck in an EOS loop.
var eosMarkers = []string{", ", " and ", " - ", ". ", " but "}

// promptVariation returns a small instruction suffix for retry attempts > 1.
// Each variation changes the prompt hash → different seed → different logprobs →
// genuinely different cover text. The decoder tries matching variations until one works.
func promptVariation(attempt int) string {
	if attempt <= 1 {
		return ""
	}
	variations := []string{
		"\nKeep it brief.",
		"\nBe casual.",
		"\nChat naturally.",
		"\nKeep it simple.",
		"\nSound friendly.",
		"\nBe relaxed.",
		"\nStay natural.",
		"\nBe genuine.",
		"\nKeep it real.",
		"\nSound human.",
		"\nBe authentic.",
	}
	return variations[(attempt-2)%len(variations)]
}

// generateWithBits generates text while embedding bits through token selection from logprobs.
func (e *Encoder) generateWithBits(ctx context.Context, instruction string, bits []bool) (string, int, int, error) {
	var result strings.Builder
	bitIndex := 0
	tokenCount := 0
	eosRecoveries := 0

	for bitIndex < len(bits) {
		bitsToEncode := min(BitsPerDecision, len(bits)-bitIndex)
		currentPrompt := e.formatPrompt(instruction, result.String())

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

		// Check for EOS: no usable logprobs means model wants to stop
		noLogprobs := len(logprobItems) == 0 || len(logprobItems[0].TopLogprobs) == 0

		var candidates []llm.LogprobToken
		if !noLogprobs {
			candidates = filterCoverCandidates(logprobItems[0].TopLogprobs)
			if result.Len() > 0 {
				candidates = filterSpaceAware(candidates, result.String()[result.Len()-1])
			}
		}

		// EOS recovery: model hit end-of-sequence or all candidates filtered out.
		// Insert a rotating continuation marker to restart generation flow.
		// The decoder detects EOS at the same position and expects the same marker.
		if noLogprobs || len(candidates) == 0 {
			if eosRecoveries >= len(eosMarkers) {
				break // give up after exhausting all markers
			}
			result.WriteString(eosMarkers[eosRecoveries])
			eosRecoveries++
			tokenCount++
			continue
		}

		// Use token-hash encoding: assign bits based on hash of token content,
		// not candidate index. This is immune to GPU-caused candidate reordering.
		// IMPORTANT: Use the same bit-width determination as the decoder
		// (all hash slots must be covered) to keep bit streams in sync.
		numSlots := 1 << bitsToEncode
		hashSet := make(map[int]bool)
		for _, c := range candidates {
			hashSet[tokenHashValue(c.Token, numSlots)] = true
		}
		for bitsToEncode > 0 && len(hashSet) < (1<<bitsToEncode) {
			bitsToEncode--
			numSlots = 1 << bitsToEncode
			hashSet = make(map[int]bool)
			for _, c := range candidates {
				hashSet[tokenHashValue(c.Token, numSlots)] = true
			}
		}

		if bitsToEncode == 0 {
			// No bits can be encoded at this position — write top candidate
			result.WriteString(candidates[0].Token)
			tokenCount++
			continue
		}

		targetValue := bitsToInt(bits[bitIndex:bitIndex+bitsToEncode]) % numSlots
		selectedToken := ""
		for _, c := range candidates {
			if tokenHashValue(c.Token, numSlots) == targetValue {
				selectedToken = c.Token
				break
			}
		}
		if selectedToken == "" {
			result.WriteString(candidates[0].Token)
			tokenCount++
			continue
		}
		result.WriteString(selectedToken)
		tokenCount++
		bitIndex += bitsToEncode

		if tokenCount > 500 {
			break
		}
	}

	// Tail generation: continue generating tokens (without encoding bits) until
	// the sentence ends naturally. This avoids mid-sentence cutoffs like
	// "hope you manage to squeeze out a" and produces complete sentences.
	if bitIndex >= len(bits) {
		tailText := result.String()
		for i := 0; i < 20; i++ {
			trimmed := strings.TrimSpace(tailText)
			if len(trimmed) > 0 {
				last := trimmed[len(trimmed)-1]
				if last == '.' || last == '!' || last == '?' {
					break
				}
			}
			currentPrompt := e.formatPrompt(instruction, tailText)
			resp, err := e.llmClient.Generate(ctx, currentPrompt, llm.GenerateOptions{
				Temperature: 0.8,
				TopK:        40,
				NumPredict:  1,
				Seed:        promptToSeed(currentPrompt),
			}, false)
			if err != nil || resp.Response == "" {
				// Model hit EOS during tail — force a sentence ending
				tailText += "."
				break
			}
			if !isASCIIOnly(resp.Response) || strings.ContainsAny(resp.Response, "\n\r\t") {
				tailText += "."
				break
			}
			tailText += resp.Response
			tokenCount++
		}
		result.Reset()
		result.WriteString(tailText)
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
	instruction := fmt.Sprintf(`Your friend texted you about %s: "%s"
Reply in 1 short sentence in English. Casual, lowercase, no quotes, no explanations. English only.`, topic, receivedMessage)
	prompt := e.formatPrompt(instruction, "")

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
	// Strip non-ASCII characters (Qwen may switch to Chinese)
	reply = stripNonASCII(reply)
	// Strip any ChatML template markers that leak through
	reply = stripChatMLMarkers(reply)
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
	return d.DecodeWithPeerReplies(ctx, coverText, topic, nil, nil)
}

// DecodeWithPeerReplies decodes cover segments with optional per-segment peer replies.
// peerReplies maps to segments 2..N (i.e. peerReplies[0] is for segment 2).
// attempts contains the 1-based retry attempt used per segment (nil = all attempt 1).
func (d *Decoder) DecodeWithPeerReplies(ctx context.Context, coverText string, topic string, peerReplies []string, attempts []int) (*DecodeResult, error) {
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
		attempt := 1
		if i < len(attempts) && attempts[i] > 0 {
			attempt = attempts[i]
		}
		decoded, err := d.decodeSegment(ctx, segment, segmentPrompt, attempt)
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

// formatPrompt builds the full prompt for stego decoding.
// Uses the ChatML template to match the encoder behavior.
func (d *Decoder) formatPrompt(instruction, assistantText string) string {
	tmpl := d.llmClient.GetChatTemplate()
	if tmpl != nil {
		return tmpl.FormatPrompt(instruction, assistantText)
	}
	return instruction + assistantText
}

func (d *Decoder) decodeSegment(ctx context.Context, coverText string, instruction string, attempt int) (*DecodeResult, error) {
	instruction = instruction + promptVariation(attempt)
	// Extract bits by matching tokens against logprobs at each position
	var extractedBits []bool
	var assistantText strings.Builder // accumulated matched tokens
	remainingText := coverText
	tokenCount := 0
	// allowTrimmed is true only for the first token, where TrimSpace during
	// encoding may have removed a leading space from the cover text.
	allowTrimmed := true
	// expectedTotalBits is set once the 2-byte length prefix is decoded.
	// It lets us limit extraction to exactly the number of bits the encoder
	// produced, preventing over-extraction at the last token.
	expectedTotalBits := 0
	eosRecoveries := 0

	for len(remainingText) > 0 {
		// Check if we've extracted enough bits
		if expectedTotalBits > 0 && len(extractedBits) >= expectedTotalBits {
			break
		}

		currentPrompt := d.formatPrompt(instruction, assistantText.String())

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

		// Check for EOS: same condition as encoder
		noLogprobs := len(logprobItems) == 0 || len(logprobItems[0].TopLogprobs) == 0

		var candidates []llm.LogprobToken
		if !noLogprobs {
			candidates = filterCoverCandidates(logprobItems[0].TopLogprobs)
			if assistantText.Len() > 0 {
				candidates = filterSpaceAware(candidates, assistantText.String()[assistantText.Len()-1])
			}
		}

		// EOS recovery: encoder inserted a rotating marker here, consume it
		if noLogprobs || len(candidates) == 0 {
			if eosRecoveries < len(eosMarkers) {
				marker := eosMarkers[eosRecoveries]
				if strings.HasPrefix(remainingText, marker) {
					remainingText = remainingText[len(marker):]
					assistantText.WriteString(marker)
					eosRecoveries++
					tokenCount++
					continue
				}
			}
			// No marker found — can't continue
			break
		}

		// Token-hash decoding: match token in cover text against candidates,
		// then compute hash to extract bits (immune to candidate reordering).

		// Determine max bits for this position: use remaining count if known
		maxBitsThisToken := BitsPerDecision
		if expectedTotalBits > 0 {
			remaining := expectedTotalBits - len(extractedBits)
			if remaining <= 0 {
				break
			}
			maxBitsThisToken = min(BitsPerDecision, remaining)
		}

		// Determine how many bit-slots exist for these candidates
		numSlots := 1 << maxBitsThisToken
		bitsToExtract := maxBitsThisToken
		// Check if enough distinct hash values exist among candidates
		hashSet := make(map[int]bool)
		for _, c := range candidates {
			hashSet[tokenHashValue(c.Token, numSlots)] = true
		}
		for bitsToExtract > 0 && len(hashSet) < (1<<bitsToExtract) {
			bitsToExtract--
			numSlots = 1 << bitsToExtract
			hashSet = make(map[int]bool)
			for _, c := range candidates {
				hashSet[tokenHashValue(c.Token, numSlots)] = true
			}
		}

		// Find which candidate token matches the start of remainingText
		matchedToken := ""
		actualConsumed := ""
		for _, cand := range candidates {
			token := cand.Token
			if strings.HasPrefix(remainingText, token) {
				matchedToken = token
				actualConsumed = token
				break
			}
			// Trimmed match only for the very first token (handles TrimSpace)
			if allowTrimmed {
				trimmedToken := strings.TrimLeft(token, " ")
				if trimmedToken != token && trimmedToken != "" && strings.HasPrefix(remainingText, trimmedToken) {
					matchedToken = token
					actualConsumed = trimmedToken
					break
				}
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

		if bitsToExtract > 0 {
			hashVal := tokenHashValue(matchedToken, 1<<bitsToExtract)
			bits := intToBits(hashVal, bitsToExtract)
			extractedBits = append(extractedBits, bits...)
		}

		// After first successful match, disable trimmed matching
		allowTrimmed = false

		// Advance past matched token
		if actualConsumed != "" {
			remainingText = strings.TrimPrefix(remainingText, actualConsumed)
			assistantText.WriteString(matchedToken) // Use original token for prompt
		}
		tokenCount++

		// Once we have the 2-byte length prefix, compute expected total bits
		if expectedTotalBits == 0 && len(extractedBits) >= 16 {
			prefix := bitsToBytes(extractedBits[:16])
			pLen := int(binary.BigEndian.Uint16(prefix))
			if pLen > 0 && pLen <= MaxSecretLength {
				expectedTotalBits = (2 + pLen) * 8
			}
		}

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

// filterSpaceAware enforces natural spacing between words. When the last
// character of the generated text is a letter or digit, only keep candidates
// that start with a space or punctuation (to avoid concatenated words like
// "supposedtobe12"). Both encoder and decoder call this identically so they
// agree on the candidate set.
func filterSpaceAware(candidates []llm.LogprobToken, lastChar byte) []llm.LogprobToken {
	if !isLetterOrDigit(lastChar) {
		return candidates
	}
	filtered := make([]llm.LogprobToken, 0, len(candidates))
	for _, c := range candidates {
		if len(c.Token) > 0 && (c.Token[0] == ' ' || isPunctuation(c.Token[0])) {
			filtered = append(filtered, c)
		}
	}
	if len(filtered) == 0 {
		return candidates // fallback: don't starve encoding
	}
	return filtered
}

func isLetterOrDigit(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isPunctuation(c byte) bool {
	switch c {
	case '.', ',', '!', '?', ';', ':', '\'', '"', ')', '-':
		return true
	}
	return false
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
	if strings.ContainsAny(token, "\n\r\t[]{}<>_") {
		return false
	}
	if containsInvisible(token) {
		return false
	}
	// Reject non-ASCII tokens (Chinese, emojis, etc.) to ensure English-only output
	if !isASCIIOnly(token) {
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

// stripNonASCII removes non-ASCII characters from a string.
// Used to clean up GenerateReply output when Qwen switches to Chinese.
func stripNonASCII(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r <= 127 {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// stripChatMLMarkers removes ChatML template tokens that Qwen may leak into output.
func stripChatMLMarkers(s string) string {
	s = strings.ReplaceAll(s, "<|im_start|>", "")
	s = strings.ReplaceAll(s, "<|im_end|>", "")
	s = strings.ReplaceAll(s, "<|endoftext|>", "")
	return strings.TrimSpace(s)
}

// isASCIIOnly returns true if the string contains only ASCII characters.
// Used to filter out Chinese, emojis, and other non-ASCII tokens from multilingual models.
func isASCIIOnly(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
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
	if strings.ContainsAny(text, "[]{}<>_") {
		return false
	}
	if containsInvisible(text) {
		return false
	}
	// Reject non-ASCII text (Chinese, emojis, etc.) to ensure English-only cover
	if !isASCIIOnly(text) {
		return false
	}

	words := strings.Fields(text)
	// Minimum reduced to 5 for smaller segment payloads
	if len(words) < 5 || len(words) > 90 {
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
// tokenHashValue maps a token string to a deterministic bit value in [0, numSlots).
// This is used instead of candidate index to encode/decode bits, making the system
// immune to GPU-caused candidate reordering between encode and decode.
func tokenHashValue(token string, numSlots int) int {
	h := fnv.New32a()
	h.Write([]byte(token))
	return int(h.Sum32()) % numSlots
}

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
