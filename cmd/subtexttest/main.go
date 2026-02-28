// Minimal test of single-segment encode + decode with debug output.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cy/subtext/internal/crypto"
	"github.com/cy/subtext/internal/llm"
	"github.com/cy/subtext/internal/subtext"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := llm.NewClient(
		llm.WithBaseURL("http://localhost:11434"),
		llm.WithModel("qwen2.5:14b"),
	)

	// Fetch template
	tmpl, err := client.FetchChatTemplate(ctx)
	if err != nil {
		log.Fatalf("template: %v", err)
	}
	if tmpl != nil {
		fmt.Printf("Template system: %q\n", tmpl.SystemMessage[:min(40, len(tmpl.SystemMessage))])
	}

	// Warm up model
	warmCtx, warmCancel := context.WithTimeout(context.Background(), 30*time.Second)
	client.Generate(warmCtx, "hello", llm.GenerateOptions{NumPredict: 1}, false)
	warmCancel()
	fmt.Println("Model warm-up done")

	// Create encoder + decoder
	enc := subtext.NewEncoder(client)
	dec := subtext.NewDecoder(client)

	// Test cases: raw bytes and real encrypted messages
	testCases := []struct {
		name    string
		payload []byte
		topic   string
	}{
		{"4 bytes raw", []byte{0xDE, 0xAD, 0xBE, 0xEF}, "fitness"},
	}

	// Add real encrypted message tests
	dummyKey := make([]byte, 32)
	for i := range dummyKey {
		dummyKey[i] = byte(i)
	}

	messages := []struct {
		name string
		text string
	}{
		{"short msg", "hi"},
		{"medium msg", "meet me at 3pm"},
		{"long msg", "meet me at the coffee shop on 5th street tomorrow at 3pm"},
	}

	for _, msg := range messages {
		encrypted, err := crypto.CompactEncrypt(dummyKey, []byte(msg.text))
		if err != nil {
			log.Fatalf("encrypt %s: %v", msg.name, err)
		}
		testCases = append(testCases, struct {
			name    string
			payload []byte
			topic   string
		}{
			fmt.Sprintf("%s (%d chars -> %d bytes encrypted)", msg.name, len(msg.text), len(encrypted)),
			encrypted,
			"casual chat",
		})
	}

	for _, tc := range testCases {
		fmt.Printf("\n%s\n%s\n", tc.name, strings.Repeat("=", 60))
		fmt.Printf("Payload: %s (%d bytes)\n", hex.EncodeToString(tc.payload), len(tc.payload))

		result, err := enc.Encode(ctx, tc.payload, tc.topic)
		if err != nil {
			log.Printf("encode %s: %v", tc.name, err)
			continue
		}

		words := strings.Fields(result.CoverText)
		fmt.Printf("\nCover text (%d bits, %d tokens, %d chars, %d words):\n%s\n",
			result.BitsEncoded, result.TokenCount, len(result.CoverText), len(words), result.CoverText)

		decoded, err := dec.Decode(ctx, result.CoverText, tc.topic)
		if err != nil {
			log.Printf("decode %s: %v", tc.name, err)
			continue
		}

		if decoded.Valid && hex.EncodeToString(decoded.EncryptedPayload) == hex.EncodeToString(tc.payload) {
			fmt.Println("✅ Round-trip SUCCESS!")
		} else {
			fmt.Printf("❌ FAIL (valid=%v, got=%s)\n", decoded.Valid, hex.EncodeToString(decoded.EncryptedPayload))
		}
	}
}
