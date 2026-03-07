// Package subtext implements steganographic encoding/decoding using LLM-based text generation.
package subtext

import (
	"context"
	"crypto/rand"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/cy/subtext/internal/llm"
)

const (
	// MaxSecretLength is the maximum encrypted payload length per segment in bytes
	MaxSecretLength = 256
	// TargetSegmentPayloadLength is the target encrypted payload size per generated cover segment.
	// Smaller segments produce shorter, more natural cover text at the cost of more segments.
	// With arithmetic coding: 10 payload + 1 length prefix = 11 bytes = 88 bits + 40 padding.
	// Each segment produces ~25-30 tokens of natural-sounding text.
	TargetSegmentPayloadLength = 10
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

	// Add a 1-byte length prefix so each segment can be decoded independently.
	// Max segment payload is TargetSegmentPayloadLength (20), so uint8 suffices.
	payloadWithLen := make([]byte, 1+len(encryptedPayload))
	payloadWithLen[0] = byte(len(encryptedPayload))
	copy(payloadWithLen[1:], encryptedPayload)

	bits := bytesToBits(payloadWithLen)
	log.Printf("[stego] encodeSegment: %d bits to encode", len(bits))
	for attempt := 1; attempt <= MaxSegmentEncodeAttempts; attempt++ {
		attemptPrompt := prompt + promptVariation(attempt)
		coverText, tokenCount, bitsEncoded, err := e.generateWithBits(ctx, attemptPrompt, bits)
		if err != nil {
			log.Printf("[stego] attempt %d: error: %v", attempt, err)
			if attempt == MaxSegmentEncodeAttempts {
				return "", 0, 0, 0, fmt.Errorf("generation failed: %w", err)
			}
			continue
		}
		if bitsEncoded != len(bits) {
			log.Printf("[stego] attempt %d: incomplete %d/%d bits, %d tokens", attempt, bitsEncoded, len(bits), tokenCount)
			if attempt == MaxSegmentEncodeAttempts {
				return "", 0, 0, 0, fmt.Errorf("incomplete segment encoding: encoded %d of %d bits", bitsEncoded, len(bits))
			}
			continue
		}
		if !isValidCoverSegment(coverText) {
			log.Printf("[stego] attempt %d: quality check failed: %q (reason: %s)", attempt, coverText[:min(80, len(coverText))], coverRejectReason(coverText))
			if attempt == MaxSegmentEncodeAttempts {
				return "", 0, 0, 0, fmt.Errorf("generated segment failed quality checks")
			}
			continue
		}
		log.Printf("[stego] attempt %d: OK, %d tokens, text=%q", attempt, tokenCount, coverText[:min(80, len(coverText))])
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
var eosMarkers = []string{
	", ", " and ", " - ", ". ", " but ",
	"; ", " so ", " then ", " or ", " also ",
	" -- ", " plus ", " anyway ", " yet ", " still ",
}

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

// generateWithBits generates text while embedding bits through arithmetic coding.
// Uses LLM logprob distributions to select tokens that encode message bits.
func (e *Encoder) generateWithBits(ctx context.Context, instruction string, bits []bool) (string, int, int, error) {
	var result strings.Builder
	enc := NewArithEncoder(bits)
	originalBitLen := len(bits)
	tokenCount := 0
	eosRecoveries := 0

	for !enc.Done(originalBitLen) {
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

		// Build quantized distribution and select token via arithmetic coding
		dist := buildDistribution(candidates)
		token := enc.EncodeStep(dist)
		result.WriteString(token)
		tokenCount++

		if tokenCount > 500 {
			break
		}
	}

	// Tail generation: continue generating tokens (without encoding bits) until
	// the sentence ends naturally. This avoids mid-sentence cutoffs like
	// "hope you manage to squeeze out a" and produces complete sentences.
	if enc.Done(originalBitLen) {
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

	if !enc.Done(originalBitLen) {
		// Not enough tokens generated to push all bits through the AC pipeline.
		// Report 0 bits so encodeSegment retries with a different prompt.
		return strings.TrimSpace(result.String()), tokenCount, 0, nil
	}
	return strings.TrimSpace(result.String()), tokenCount, originalBitLen, nil
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
	log.Printf("[stego-dec] decodeSegment: coverText=%d chars, attempt=%d", len(coverText), attempt)

	dec := NewArithDecoder()
	var assistantText strings.Builder // accumulated matched tokens
	remainingText := coverText
	tokenCount := 0
	// allowTrimmed is true only for the first token, where TrimSpace during
	// encoding may have removed a leading space from the cover text.
	allowTrimmed := true
	// expectedTotalBits is set once the 2-byte length prefix is decoded.
	// Used as an early-stop optimization to avoid unnecessary LLM calls.
	expectedTotalBits := 0
	eosRecoveries := 0

	for len(remainingText) > 0 {
		// Early stop: we have enough bits for the full payload
		if expectedTotalBits > 0 && dec.BitsRecovered() >= expectedTotalBits {
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

		// Build distribution (same canonical ordering as encoder)
		dist := buildDistribution(candidates)

		// Find the LONGEST distribution token matching the start of remainingText.
		// Must use longest match because shorter tokens may be prefixes of the
		// actual token the encoder selected (e.g. " H" vs " Heading").
		matchedToken := ""
		actualConsumed := ""
		for _, tok := range dist.Tokens {
			if strings.HasPrefix(remainingText, tok.Token) && len(tok.Token) > len(actualConsumed) {
				matchedToken = tok.Token
				actualConsumed = tok.Token
			}
			// Trimmed match only for the very first token (handles TrimSpace)
			if allowTrimmed {
				trimmedToken := strings.TrimLeft(tok.Token, " ")
				if trimmedToken != tok.Token && trimmedToken != "" && strings.HasPrefix(remainingText, trimmedToken) && len(trimmedToken) > len(actualConsumed) {
					matchedToken = tok.Token
					actualConsumed = trimmedToken
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

		// Arithmetic decode step: recover bits from this token
		if err := dec.DecodeStep(dist, matchedToken); err != nil {
			return nil, fmt.Errorf("arithmetic decode step failed: %w", err)
		}

		// After first successful match, disable trimmed matching
		allowTrimmed = false

		// Advance past matched token
		remainingText = strings.TrimPrefix(remainingText, actualConsumed)
		assistantText.WriteString(matchedToken) // Use original token for prompt
		tokenCount++

		// Once we have the 1-byte length prefix, compute expected total bits
		if expectedTotalBits == 0 && dec.BitsRecovered() >= 8 {
			prefix := bitsToBytes(dec.Bits()[:8])
			pLen := int(prefix[0])
			if pLen > 0 && pLen <= MaxSecretLength {
				expectedTotalBits = (1 + pLen) * 8
			}
		}

		// Safety limits
		if tokenCount > 500 || dec.BitsRecovered() > (MaxSecretLength+1)*8+PaddingBits+100 {
			break
		}
	}

	dec.Flush()
	extractedBits := dec.Bits()
	log.Printf("[stego-dec] recovered %d bits, %d tokens, remaining=%d chars", len(extractedBits), tokenCount, len(remainingText))

	// Convert bits back to bytes
	extractedBytes := bitsToBytes(extractedBits)
	if len(extractedBytes) < 1 {
		log.Printf("[stego-dec] not enough bytes: %d", len(extractedBytes))
		return &DecodeResult{Valid: false}, nil
	}

	// Parse 1-byte length prefix
	payloadLen := int(extractedBytes[0])
	log.Printf("[stego-dec] length prefix=%d, available=%d", payloadLen, len(extractedBytes)-1)

	if payloadLen > len(extractedBytes)-1 || payloadLen > MaxSecretLength {
		log.Printf("[stego-dec] invalid length: %d (have %d bytes)", payloadLen, len(extractedBytes)-1)
		return &DecodeResult{Valid: false}, nil
	}

	payload := extractedBytes[1 : 1+payloadLen]

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
- 1 to 3 casual sentences
- 15 to 40 words total
- use full standard English words, no abbreviations or texting slang
- plain conversational tone, mostly lowercase
- mundane and specific (like normal daily life)
- no bullets, no lists, no quotes
- no brackets or parentheses
- no emojis, emoticons, or special characters
- no hyphens connecting words
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

// makePrefixFree removes candidates whose token is a prefix of another candidate.
// This ensures unambiguous token matching during decode (the decoder uses longest
// match, so two tokens where one is a prefix of another would cause ambiguity).
//
// Strategy: prefer LONGER tokens over shorter ones. Longer tokens are more unique
// (less likely to be prefixes of each other) and preserving more candidates increases
// the per-token information content dramatically. For example, keeping {" they",
// " there", " them", " think"} (4 candidates, ~1.7 bits) instead of {" the", " think"}
// (2 candidates, ~0.2 bits) by dropping the short prefix " the".
func makePrefixFree(candidates []llm.LogprobToken) []llm.LogprobToken {
	// Sort by token length descending so longer tokens are accepted first.
	sorted := make([]llm.LogprobToken, len(candidates))
	copy(sorted, candidates)
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i].Token) > len(sorted[j].Token)
	})

	result := make([]llm.LogprobToken, 0, len(sorted))
	for _, c := range sorted {
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
	if strings.ContainsAny(token, "\n\r\t[]{}<>_\\$@#/\"") {
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

	// Reject tokens with internal hyphens (e.g. "told-me", "at-work")
	word := strings.TrimSpace(token)
	if len(word) > 1 && strings.Contains(word[1:len(word)-1], "-") {
		return false
	}

	// Reject emoticon-like patterns
	if strings.ContainsAny(token, ":;") && strings.ContainsAny(token, ")(DP") {
		return false
	}

	// Reject consonant-only words (catches "tty", "nx", "gd", "tm" etc.)
	if len(trimmed) >= 2 && !hasVowel(trimmed) && isAlphaOnly(trimmed) {
		return false
	}

	// Reject camelCase/PascalCase tokens (code identifiers like "URLException",
	// "forIndexPath", "AppCompatActivity", "istringstream")
	if isCamelCase(word) {
		return false
	}

	return true
}

// isCamelCase returns true if s looks like a code identifier:
// a lowercase letter immediately followed by an uppercase letter (camelCase),
// or an all-lowercase word longer than 10 chars with no spaces (likely code like "istringstream").
func isCamelCase(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= 'a' && s[i-1] <= 'z' && s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	// Long all-lowercase single words are likely code identifiers
	if len(s) > 10 && isAlphaOnly(s) && strings.ToLower(s) == s {
		return true
	}
	return false
}

// hasVowel returns true if the string contains at least one vowel.
func hasVowel(s string) bool {
	for _, c := range strings.ToLower(s) {
		switch c {
		case 'a', 'e', 'i', 'o', 'u', 'y':
			return true
		}
	}
	return false
}

// isAlphaOnly returns true if the string contains only ASCII letters.
func isAlphaOnly(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
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
	if len(words) < 5 || len(words) > 150 {
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

// coverRejectReason returns a short description of why the text fails quality checks (for logging).
func coverRejectReason(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return "empty"
	}
	if strings.Contains(text, segmentSeparator) {
		return "contains separator"
	}
	if strings.Contains(text, "\n") || strings.Contains(text, "\r") {
		return "multiline"
	}
	if strings.ContainsAny(text, "[]{}<>_") {
		return fmt.Sprintf("bad char in []{}<>_")
	}
	if containsInvisible(text) {
		return "invisible chars"
	}
	if !isASCIIOnly(text) {
		return "non-ASCII"
	}
	words := strings.Fields(text)
	if len(words) < 5 {
		return fmt.Sprintf("too few words (%d)", len(words))
	}
	if len(words) > 150 {
		return fmt.Sprintf("too many words (%d)", len(words))
	}
	lower := strings.ToLower(text)
	for _, phrase := range []string{"write one sentence", "write a sentence", "hard rules", "output only", "this text", "no changes in punctuation", "optional argumentation", "include names", "instruction", "prompt"} {
		if strings.Contains(lower, phrase) {
			return fmt.Sprintf("bad phrase: %q", phrase)
		}
	}
	return "unknown"
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
