package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Keys should be different
	if bytes.Equal(kp1.PrivateKey[:], kp2.PrivateKey[:]) {
		t.Error("Generated key pairs have same private key")
	}
	if bytes.Equal(kp1.PublicKey[:], kp2.PublicKey[:]) {
		t.Error("Generated key pairs have same public key")
	}
}

func TestKeyExchange(t *testing.T) {
	// Alice generates her key pair
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Alice GenerateKeyPair failed: %v", err)
	}

	// Bob generates his key pair
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Bob GenerateKeyPair failed: %v", err)
	}

	// Both compute shared secret
	aliceShared, err := ComputeSharedSecret(alice.PrivateKey[:], bob.PublicKey[:])
	if err != nil {
		t.Fatalf("Alice ComputeSharedSecret failed: %v", err)
	}

	bobShared, err := ComputeSharedSecret(bob.PrivateKey[:], alice.PublicKey[:])
	if err != nil {
		t.Fatalf("Bob ComputeSharedSecret failed: %v", err)
	}

	// Shared secrets should match
	if !bytes.Equal(aliceShared, bobShared) {
		t.Error("Shared secrets do not match")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Generate a shared key via key exchange
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedKey, _ := ComputeSharedSecret(alice.PrivateKey[:], bob.PublicKey[:])

	testCases := []struct {
		name      string
		plaintext string
	}{
		{"empty", ""},
		{"short", "Hi"},
		{"medium", "Meet at dock 7, 9pm sharp!"},
		{"long", "This is a much longer message that spans multiple sentences. It contains lots of information that needs to be encrypted securely."},
		{"unicode", "Hello 世界! 🔐"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := NewEncryptor(sharedKey)
			if err != nil {
				t.Fatalf("NewEncryptor failed: %v", err)
			}

			ciphertext, err := enc.Encrypt([]byte(tc.plaintext))
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Ciphertext should be longer than plaintext (nonce + tag)
			if len(ciphertext) < len(tc.plaintext)+NonceSize+TagSize {
				t.Errorf("Ciphertext too short: got %d, want >= %d",
					len(ciphertext), len(tc.plaintext)+NonceSize+TagSize)
			}

			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if string(decrypted) != tc.plaintext {
				t.Errorf("Decrypted text mismatch: got %q, want %q", string(decrypted), tc.plaintext)
			}
		})
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	eve, _ := GenerateKeyPair()

	aliceKey, _ := ComputeSharedSecret(alice.PrivateKey[:], bob.PublicKey[:])
	eveKey, _ := ComputeSharedSecret(eve.PrivateKey[:], bob.PublicKey[:])

	// Encrypt with Alice's key
	enc, _ := NewEncryptor(aliceKey)
	ciphertext, _ := enc.Encrypt([]byte("secret message"))

	// Try to decrypt with Eve's key (should fail)
	eveEnc, _ := NewEncryptor(eveKey)
	_, err := eveEnc.Decrypt(ciphertext)
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	sharedKey, _ := ComputeSharedSecret(alice.PrivateKey[:], bob.PublicKey[:])

	enc, _ := NewEncryptor(sharedKey)
	ciphertext, _ := enc.Encrypt([]byte("secret message"))

	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err := enc.Decrypt(ciphertext)
	if err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed for tampered ciphertext, got %v", err)
	}
}

func TestEncryptWithKeyConvenience(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Hello, World!")

	ciphertext, err := EncryptWithKey(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}

	decrypted, err := DecryptWithKey(key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithKey failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text mismatch")
	}
}

func TestInvalidKeySize(t *testing.T) {
	shortKey := make([]byte, 16)
	_, err := NewEncryptor(shortKey)
	if err != ErrInvalidKeySize {
		t.Errorf("Expected ErrInvalidKeySize, got %v", err)
	}
}
