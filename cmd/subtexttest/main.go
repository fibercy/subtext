// Minimal test of single-segment encode + decode with debug output.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

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

	// Test with small payload: exactly 4 bytes (=> 6 bytes with prefix => 48 bits)
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	fmt.Printf("Payload: %s (%d bytes)\n", hex.EncodeToString(payload), len(payload))

	// Encode
	result, err := enc.Encode(ctx, payload, "fitness")
	if err != nil {
		log.Fatalf("encode: %v", err)
	}

	fmt.Printf("\nCover text (%d bits, %d tokens):\n%s\n", result.BitsEncoded, result.TokenCount, result.CoverText)

	// Decode
	decoded, err := dec.Decode(ctx, result.CoverText, "fitness")
	if err != nil {
		log.Fatalf("decode: %v", err)
	}

	fmt.Printf("\nDecode valid: %v\n", decoded.Valid)
	if decoded.Valid {
		fmt.Printf("Decoded payload: %s\n", hex.EncodeToString(decoded.EncryptedPayload))
		if hex.EncodeToString(decoded.EncryptedPayload) == hex.EncodeToString(payload) {
			fmt.Println("✅ Round-trip SUCCESS!")
		} else {
			fmt.Println("❌ Round-trip MISMATCH")
		}
	} else {
		fmt.Println("❌ Decode invalid")
	}
}
