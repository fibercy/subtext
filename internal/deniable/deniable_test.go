package deniable

import (
	"testing"

	"github.com/cy/stegochat/internal/crypto"
)

func TestEncryptDecryptNoDecoy(t *testing.T) {
	enc := New()

	// Generate a key
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	key := kp.PrivateKey[:]

	msg := Message{
		RealMessage: "This is the real secret message",
	}

	encrypted, err := enc.Encrypt(key, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(encrypted.Ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}
	if encrypted.DecoyKey != nil {
		t.Error("DecoyKey should be nil when no decoy provided")
	}

	// Decrypt
	decrypted, isDecoy, err := enc.Decrypt(encrypted.Ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if isDecoy {
		t.Error("isDecoy should be false for real key")
	}
	if decrypted != msg.RealMessage {
		t.Errorf("Decrypted message mismatch: got %q, want %q", decrypted, msg.RealMessage)
	}
}

func TestEncryptDecryptWithDecoy(t *testing.T) {
	enc := New()

	// Generate shared key
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	sharedKey := kp.PrivateKey[:]

	msg := Message{
		RealMessage:  "Meet at dock 7 at midnight",
		DecoyMessage: "See you at the coffee shop tomorrow!",
	}

	encrypted, err := enc.Encrypt(sharedKey, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(encrypted.Ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}
	if encrypted.DecoyKey == nil {
		t.Error("DecoyKey should not be nil when decoy provided")
	}

	// Decrypt with real key
	decrypted, isDecoy, err := enc.Decrypt(encrypted.Ciphertext, sharedKey)
	if err != nil {
		t.Fatalf("Decrypt with real key failed: %v", err)
	}
	if isDecoy {
		t.Error("isDecoy should be false for real key")
	}
	if decrypted != msg.RealMessage {
		t.Errorf("Real message mismatch: got %q, want %q", decrypted, msg.RealMessage)
	}

	// Decrypt with decoy key
	decoyDecrypted, isDecoy, err := enc.Decrypt(encrypted.Ciphertext, encrypted.DecoyKey)
	if err != nil {
		t.Fatalf("Decrypt with decoy key failed: %v", err)
	}
	if !isDecoy {
		t.Error("isDecoy should be true for decoy key")
	}
	if decoyDecrypted != msg.DecoyMessage {
		t.Errorf("Decoy message mismatch: got %q, want %q", decoyDecrypted, msg.DecoyMessage)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	enc := New()

	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	realKey := kp1.PrivateKey[:]
	wrongKey := kp2.PrivateKey[:]

	msg := Message{
		RealMessage: "Secret message",
	}

	encrypted, err := enc.Encrypt(realKey, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Try to decrypt with wrong key
	_, _, err = enc.Decrypt(encrypted.Ciphertext, wrongKey)
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecryptWithKeys(t *testing.T) {
	enc := New()

	kp, _ := crypto.GenerateKeyPair()
	sharedKey := kp.PrivateKey[:]

	msg := Message{
		RealMessage:  "Real secret",
		DecoyMessage: "Decoy message",
	}

	encrypted, err := enc.Encrypt(sharedKey, msg)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Generate some random keys
	randomKeys := make([][]byte, 3)
	for i := range randomKeys {
		kp, _ := crypto.GenerateKeyPair()
		randomKeys[i] = kp.PrivateKey[:]
	}

	// Try with real key in the list
	keys := append(randomKeys, sharedKey)
	decrypted, keyIndex, err := enc.DecryptWithKeys(encrypted.Ciphertext, keys)
	if err != nil {
		t.Fatalf("DecryptWithKeys failed: %v", err)
	}
	if keyIndex != 3 {
		t.Errorf("Expected key index 3, got %d", keyIndex)
	}
	if decrypted != msg.RealMessage {
		t.Errorf("Message mismatch: got %q", decrypted)
	}

	// Try with decoy key in the list
	keys = append(randomKeys, encrypted.DecoyKey)
	decrypted, keyIndex, err = enc.DecryptWithKeys(encrypted.Ciphertext, keys)
	if err != nil {
		t.Fatalf("DecryptWithKeys with decoy failed: %v", err)
	}
	if keyIndex != 3 {
		t.Errorf("Expected key index 3, got %d", keyIndex)
	}
	if decrypted != msg.DecoyMessage {
		t.Errorf("Decoy message mismatch: got %q", decrypted)
	}
}

func TestPadUnpadMessage(t *testing.T) {
	testCases := []struct {
		msg       string
		targetLen int
	}{
		{"short", 10},
		{"exactly10!", 10},
		{"longer than target", 10},
		{"", 5},
	}

	for _, tc := range testCases {
		padded := padMessage([]byte(tc.msg), tc.targetLen)
		unpadded := unpadMessage(padded)

		if string(unpadded) != tc.msg {
			t.Errorf("Pad/unpad roundtrip failed for %q: got %q", tc.msg, string(unpadded))
		}
	}
}

func TestEmptyMessages(t *testing.T) {
	enc := New()

	kp, _ := crypto.GenerateKeyPair()
	key := kp.PrivateKey[:]

	// Empty real message
	msg := Message{
		RealMessage: "",
	}

	encrypted, err := enc.Encrypt(key, msg)
	if err != nil {
		t.Fatalf("Encrypt empty message failed: %v", err)
	}

	decrypted, _, err := enc.Decrypt(encrypted.Ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt empty message failed: %v", err)
	}
	if decrypted != "" {
		t.Errorf("Expected empty string, got %q", decrypted)
	}
}

func TestLongMessages(t *testing.T) {
	enc := New()

	kp, _ := crypto.GenerateKeyPair()
	key := kp.PrivateKey[:]

	// Max length message
	longMsg := make([]byte, MaxPayloadSize)
	for i := range longMsg {
		longMsg[i] = byte('A' + (i % 26))
	}

	msg := Message{
		RealMessage: string(longMsg),
	}

	encrypted, err := enc.Encrypt(key, msg)
	if err != nil {
		t.Fatalf("Encrypt max length message failed: %v", err)
	}

	decrypted, _, err := enc.Decrypt(encrypted.Ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt max length message failed: %v", err)
	}
	if decrypted != msg.RealMessage {
		t.Error("Max length message roundtrip failed")
	}

	// Too long message
	tooLongMsg := Message{
		RealMessage: string(make([]byte, MaxPayloadSize+1)),
	}
	_, err = enc.Encrypt(key, tooLongMsg)
	if err != ErrPayloadTooLarge {
		t.Errorf("Expected ErrPayloadTooLarge, got %v", err)
	}
}
