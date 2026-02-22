package subtext

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cy/subtext/internal/llm"
)

// TestArithmeticLLMRoundTrip tests arithmetic coding with real LLM logprobs.
// Requires Ollama running with qwen2.5:14b. Skip if unavailable.
func TestArithmeticLLMRoundTrip(t *testing.T) {
	client := llm.NewClient()
	ctx := context.Background()

	if err := client.Ping(ctx); err != nil {
		t.Skipf("Ollama not available: %v", err)
	}
	if _, err := client.FetchChatTemplate(ctx); err != nil {
		t.Skipf("Failed to get chat template: %v", err)
	}

	// Use a small payload: 4 bytes = 1 segment
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	// Add 2-byte length prefix
	payloadWithLen := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(payloadWithLen[0:2], uint16(len(payload)))
	copy(payloadWithLen[2:], payload)
	bits := bytesToBits(payloadWithLen)
	t.Logf("payload bits: %d bits", len(bits))

	instruction := buildPrompt("weather")
	instruction += promptVariation(1) // attempt 1 = no variation

	// --- ENCODE ---
	enc := NewArithEncoder(bits)
	originalBitLen := len(bits)

	tmpl := client.GetChatTemplate()
	formatPrompt := func(instr, text string) string {
		if tmpl != nil {
			return tmpl.FormatPrompt(instr, text)
		}
		return instr + text
	}

	var encResult strings.Builder
	encTokenCount := 0
	eosRecoveries := 0

	for !enc.Done(originalBitLen) && encTokenCount < 200 {
		currentPrompt := formatPrompt(instruction, encResult.String())

		resp, err := client.Generate(ctx, currentPrompt, llm.GenerateOptions{
			Temperature: 0.8,
			TopK:        40,
			NumPredict:  1,
			Seed:        promptToSeed(currentPrompt),
		}, true)
		if err != nil {
			t.Fatalf("encode generation failed at token %d: %v", encTokenCount, err)
		}

		logprobItems, err := resp.ParseLogprobs()
		if err != nil {
			t.Fatalf("encode parse logprobs failed: %v", err)
		}

		noLogprobs := len(logprobItems) == 0 || len(logprobItems[0].TopLogprobs) == 0

		var candidates []llm.LogprobToken
		if !noLogprobs {
			candidates = filterCoverCandidates(logprobItems[0].TopLogprobs)
			if encResult.Len() > 0 {
				candidates = filterSpaceAware(candidates, encResult.String()[encResult.Len()-1])
			}
		}

		if noLogprobs || len(candidates) == 0 {
			if eosRecoveries >= len(eosMarkers) {
				t.Logf("enc: EOS exhausted at token %d", encTokenCount)
				break
			}
			marker := eosMarkers[eosRecoveries]
			t.Logf("enc step %3d: EOS recovery, marker=%q", encTokenCount, marker)
			encResult.WriteString(marker)
			eosRecoveries++
			encTokenCount++
			continue
		}

		dist := buildDistribution(candidates)
		token := enc.EncodeStep(dist)
		encResult.WriteString(token)
		encTokenCount++

		t.Logf("enc step %3d: token=%q candidates=%d consumed=%d",
			encTokenCount-1, token, len(dist.Tokens), enc.BitsConsumed())
	}

	coverText := strings.TrimSpace(encResult.String())
	bitsEncoded := enc.BitsConsumed()
	if bitsEncoded > originalBitLen {
		bitsEncoded = originalBitLen
	}

	t.Logf("\nCover text: %q", coverText)
	t.Logf("Bits encoded: %d / %d, tokens: %d\n", bitsEncoded, originalBitLen, encTokenCount)

	if bitsEncoded < originalBitLen {
		t.Fatalf("encode incomplete: %d / %d bits", bitsEncoded, originalBitLen)
	}

	// --- DECODE ---
	dec := NewArithDecoder()
	var assistantText strings.Builder
	remainingText := coverText
	decTokenCount := 0
	allowTrimmed := true
	eosRecoveries = 0

	for len(remainingText) > 0 && decTokenCount < 200 {
		currentPrompt := formatPrompt(instruction, assistantText.String())

		resp, err := client.Generate(ctx, currentPrompt, llm.GenerateOptions{
			Temperature: 0.8,
			TopK:        40,
			NumPredict:  1,
			Seed:        promptToSeed(currentPrompt),
		}, true)
		if err != nil {
			t.Fatalf("decode generation failed at token %d: %v", decTokenCount, err)
		}

		logprobItems, err := resp.ParseLogprobs()
		if err != nil {
			t.Fatalf("decode parse logprobs failed: %v", err)
		}

		noLogprobs := len(logprobItems) == 0 || len(logprobItems[0].TopLogprobs) == 0

		var candidates []llm.LogprobToken
		if !noLogprobs {
			candidates = filterCoverCandidates(logprobItems[0].TopLogprobs)
			if assistantText.Len() > 0 {
				candidates = filterSpaceAware(candidates, assistantText.String()[assistantText.Len()-1])
			}
		}

		if noLogprobs || len(candidates) == 0 {
			if eosRecoveries < len(eosMarkers) {
				marker := eosMarkers[eosRecoveries]
				if strings.HasPrefix(remainingText, marker) {
					remainingText = remainingText[len(marker):]
					assistantText.WriteString(marker)
					eosRecoveries++
					decTokenCount++
					t.Logf("dec step %3d: EOS marker=%q", decTokenCount-1, marker)
					continue
				}
			}
			t.Logf("dec: stuck at token %d, remaining=%q", decTokenCount, remainingText[:min(40, len(remainingText))])
			break
		}

		dist := buildDistribution(candidates)

		matchedToken := ""
		actualConsumed := ""
		for _, tok := range dist.Tokens {
			if strings.HasPrefix(remainingText, tok.Token) && len(tok.Token) > len(actualConsumed) {
				matchedToken = tok.Token
				actualConsumed = tok.Token
			}
			if allowTrimmed {
				trimmedToken := strings.TrimLeft(tok.Token, " ")
				if trimmedToken != tok.Token && trimmedToken != "" && strings.HasPrefix(remainingText, trimmedToken) && len(trimmedToken) > len(actualConsumed) {
					matchedToken = tok.Token
					actualConsumed = trimmedToken
				}
			}
		}

		if matchedToken == "" {
			t.Logf("dec step %3d: NO MATCH for %q, candidates=%d, skipping char",
				decTokenCount, remainingText[:min(20, len(remainingText))], len(dist.Tokens))
			// Log first few candidates for debugging
			for i, tok := range dist.Tokens {
				if i >= 5 {
					break
				}
				t.Logf("  candidate: %q", tok.Token)
			}
			remainingText = remainingText[1:]
			continue
		}

		prevBits := dec.BitsRecovered()
		if err := dec.DecodeStep(dist, matchedToken); err != nil {
			t.Fatalf("decode step failed: %v", err)
		}
		newBits := dec.BitsRecovered() - prevBits

		allowTrimmed = false
		remainingText = strings.TrimPrefix(remainingText, actualConsumed)
		assistantText.WriteString(matchedToken)
		decTokenCount++

		t.Logf("dec step %3d: token=%q candidates=%d recovered=%d(+%d)",
			decTokenCount-1, matchedToken, len(dist.Tokens), dec.BitsRecovered(), newBits)
	}

	dec.Flush()
	extractedBits := dec.Bits()
	t.Logf("\nTotal bits recovered: %d", len(extractedBits))

	extractedBytes := bitsToBytes(extractedBits)
	if len(extractedBytes) < 2 {
		t.Fatalf("not enough bytes: %d", len(extractedBytes))
	}

	pLen := int(binary.BigEndian.Uint16(extractedBytes[0:2]))
	t.Logf("Decoded length prefix: %d", pLen)

	if pLen > len(extractedBytes)-2 || pLen > MaxSecretLength {
		t.Fatalf("invalid length: %d (have %d bytes)", pLen, len(extractedBytes)-2)
	}

	recovered := extractedBytes[2 : 2+pLen]
	t.Logf("Recovered payload: %x", recovered)
	t.Logf("Original payload:  %x", payload)

	if fmt.Sprintf("%x", recovered) != fmt.Sprintf("%x", payload) {
		t.Errorf("MISMATCH: got %x, want %x", recovered, payload)
	} else {
		t.Log("Round-trip SUCCESS!")
	}

	// Cleanup
	os.Remove("internal/stego/prompt.txt")
}
