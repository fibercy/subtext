package subtext

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/cy/subtext/internal/crypto"
	"github.com/cy/subtext/internal/llm"
)

// setupLLM creates a client and skips the test if Ollama is unavailable.
func setupLLM(t *testing.T) (*llm.Client, context.Context) {
	t.Helper()
	client := llm.NewClient()
	ctx := context.Background()

	if err := client.Ping(ctx); err != nil {
		t.Skipf("Ollama not available: %v", err)
	}
	if _, err := client.FetchChatTemplate(ctx); err != nil {
		t.Skipf("Failed to get chat template: %v", err)
	}
	return client, ctx
}

// dummyKey is a fixed key for deterministic encrypted test payloads.
var dummyKey = func() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}()

// testEncryptRoundTrip encrypts secret, encodes into cover text, decodes, decrypts, and verifies.
// Retries up to 3 times since CompactEncrypt uses a random nonce, and some encrypted payloads
// cause LLM candidate-set disagreements between encode and decode.
func testEncryptRoundTrip(t *testing.T, client *llm.Client, ctx context.Context, secret, topic string) {
	t.Helper()

	t.Logf("Secret: %q (%d bytes)", secret, len(secret))

	const maxAttempts = 5
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			t.Logf("--- retry %d/%d (new random nonce) ---", attempt, maxAttempts)
		}

		encrypted, err := crypto.CompactEncrypt(dummyKey, []byte(secret))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		t.Logf("Encrypted: %s (%d bytes)", hex.EncodeToString(encrypted), len(encrypted))

		enc := NewEncoder(client)
		result, err := enc.Encode(ctx, encrypted, topic)
		if err != nil {
			t.Logf("encode failed: %v", err)
			continue
		}

		words := strings.Fields(result.CoverText)
		segments := strings.Count(result.CoverText, segmentSeparator) + 1
		t.Logf("Cover:     %q", result.CoverText)
		t.Logf("Stats:     %d segments, %d tokens, %d chars, %d words",
			segments, result.TokenCount, len(result.CoverText), len(words))

		dec := NewDecoder(client)
		decoded, err := dec.Decode(ctx, result.CoverText, topic)
		if err != nil {
			t.Logf("decode error: %v", err)
			continue
		}
		if !decoded.Valid {
			t.Logf("decode returned invalid")
			continue
		}

		decrypted, err := crypto.CompactDecrypt(dummyKey, decoded.EncryptedPayload)
		if err != nil {
			t.Logf("decrypt failed: %v", err)
			continue
		}

		t.Logf("Recovered: %q", string(decrypted))

		if string(decrypted) != secret {
			t.Logf("MISMATCH: got %q, want %q", string(decrypted), secret)
			continue
		}

		t.Logf("Round-trip SUCCESS (attempt %d)", attempt)
		return
	}

	t.Fatalf("all %d attempts failed for secret %q", maxAttempts, secret)
}

func TestStegoShort(t *testing.T) {
	client, ctx := setupLLM(t)
	testEncryptRoundTrip(t, client, ctx, "hi", "casual chat")
}

func TestStegoMedium(t *testing.T) {
	client, ctx := setupLLM(t)
	testEncryptRoundTrip(t, client, ctx, "meet me at 3pm", "casual chat")
}

func TestStegoLong(t *testing.T) {
	client, ctx := setupLLM(t)
	testEncryptRoundTrip(t, client, ctx,
		"meet me at the coffee shop on 5th street tomorrow at 3pm",
		"weekend plans")
}

// TestArithmeticLLMRoundTrip tests low-level arithmetic coding with real LLM logprobs.
func TestArithmeticLLMRoundTrip(t *testing.T) {
	client := llm.NewClient()
	ctx := context.Background()

	if err := client.Ping(ctx); err != nil {
		t.Skipf("Ollama not available: %v", err)
	}
	if _, err := client.FetchChatTemplate(ctx); err != nil {
		t.Skipf("Failed to get chat template: %v", err)
	}

	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	payloadWithLen := make([]byte, 1+len(payload))
	payloadWithLen[0] = byte(len(payload))
	copy(payloadWithLen[1:], payload)
	bits := bytesToBits(payloadWithLen)
	t.Logf("payload bits: %d bits", len(bits))

	instruction := buildPrompt("weather")
	instruction += promptVariation(1)

	tmpl := client.GetChatTemplate()
	formatPrompt := func(instr, text string) string {
		if tmpl != nil {
			return tmpl.FormatPrompt(instr, text)
		}
		return instr + text
	}

	// --- ENCODE ---
	enc := NewArithEncoder(bits)
	originalBitLen := len(bits)

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
				break
			}
			encResult.WriteString(eosMarkers[eosRecoveries])
			eosRecoveries++
			encTokenCount++
			continue
		}

		dist := buildDistribution(candidates)
		token := enc.EncodeStep(dist)
		encResult.WriteString(token)
		encTokenCount++
	}

	coverText := strings.TrimSpace(encResult.String())
	bitsEncoded := enc.BitsConsumed()
	if bitsEncoded > originalBitLen {
		bitsEncoded = originalBitLen
	}

	t.Logf("Cover text: %q", coverText)
	t.Logf("Bits encoded: %d / %d, tokens: %d", bitsEncoded, originalBitLen, encTokenCount)

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
					continue
				}
			}
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
			remainingText = remainingText[1:]
			continue
		}

		if err := dec.DecodeStep(dist, matchedToken); err != nil {
			t.Fatalf("decode step failed: %v", err)
		}

		allowTrimmed = false
		remainingText = strings.TrimPrefix(remainingText, actualConsumed)
		assistantText.WriteString(matchedToken)
		decTokenCount++
	}

	dec.Flush()
	extractedBits := dec.Bits()
	extractedBytes := bitsToBytes(extractedBits)
	if len(extractedBytes) < 1 {
		t.Fatalf("not enough bytes: %d", len(extractedBytes))
	}

	pLen := int(extractedBytes[0])
	if pLen > len(extractedBytes)-1 || pLen > MaxSecretLength {
		t.Fatalf("invalid length: %d (have %d bytes)", pLen, len(extractedBytes)-1)
	}

	recovered := extractedBytes[1 : 1+pLen]
	if fmt.Sprintf("%x", recovered) != fmt.Sprintf("%x", payload) {
		t.Errorf("MISMATCH: got %x, want %x", recovered, payload)
	} else {
		t.Log("Round-trip SUCCESS!")
	}
}
