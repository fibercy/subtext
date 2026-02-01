// Package deniable implements deniable encryption with multiple decryption keys.
//
// Deniable encryption allows a single ciphertext to decrypt to different
// plaintexts depending on which key is used. This provides plausible deniability -
// if coerced, a user can reveal a decoy key that decrypts to an innocent message.
package deniable

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cy/stegochat/internal/crypto"
)

var (
	ErrPayloadTooLarge   = errors.New("payload too large for deniable encryption")
	ErrInvalidCiphertext = errors.New("invalid deniable ciphertext")
	ErrDecryptionFailed  = errors.New("decryption failed - key mismatch or corrupted data")
)

const (
	// MaxPayloadSize is the maximum size of a single message
	MaxPayloadSize = 64
	// HeaderSize is the size of the deniable encryption header
	HeaderSize = 4
	// Version is the current deniable encryption format version
	Version = 1
)

// Message represents a message with optional decoy
type Message struct {
	RealMessage  string
	DecoyMessage string
}

// EncryptedMessage contains the deniable ciphertext
type EncryptedMessage struct {
	Ciphertext []byte
	RealKey    []byte
	DecoyKey   []byte // Only set if decoy message was provided
}

// DeniableEncryptor handles deniable encryption
type DeniableEncryptor struct{}

// New creates a new DeniableEncryptor
func New() *DeniableEncryptor {
	return &DeniableEncryptor{}
}

// Encrypt encrypts a message with optional decoy using deniable encryption.
//
// The encryption scheme stores both the real ciphertext and decoy ciphertext
// in the combined output. Each can only be decrypted with its respective key.
//
// Format:
// - [version (1)] [flags (1)] [real_len (2)] [real_ciphertext] [decoy_len (2)] [decoy_ciphertext]
//
// Both ciphertexts are independently encrypted with AES-256-GCM, so:
// - Real key decrypts real_ciphertext
// - Decoy key decrypts decoy_ciphertext
func (d *DeniableEncryptor) Encrypt(sharedKey []byte, msg Message) (*EncryptedMessage, error) {
	if len(msg.RealMessage) > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}
	if len(msg.DecoyMessage) > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}

	// Pad messages to same length for indistinguishability
	maxLen := max(len(msg.RealMessage), len(msg.DecoyMessage))
	if maxLen == 0 {
		maxLen = 1
	}

	realPadded := padMessage([]byte(msg.RealMessage), maxLen)

	// Encrypt real message
	realCiphertext, err := crypto.EncryptWithKey(sharedKey, realPadded)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt real message: %w", err)
	}

	result := &EncryptedMessage{
		RealKey: sharedKey,
	}

	if msg.DecoyMessage != "" {
		decoyPadded := padMessage([]byte(msg.DecoyMessage), maxLen)

		// Generate decoy key
		decoyKey := make([]byte, crypto.KeySize)
		if _, err := rand.Read(decoyKey); err != nil {
			return nil, fmt.Errorf("failed to generate decoy key: %w", err)
		}

		// Encrypt decoy message with decoy key
		decoyCiphertext, err := crypto.EncryptWithKey(decoyKey, decoyPadded)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt decoy message: %w", err)
		}

		// Create combined ciphertext with both encrypted messages
		// [version (1)] [flags (1)] [real_len (2)] [real_ciphertext] [decoy_len (2)] [decoy_ciphertext]
		combined := make([]byte, 0, 4+len(realCiphertext)+2+len(decoyCiphertext))
		combined = append(combined, Version)
		combined = append(combined, 0x01) // Flag: has decoy
		combined = append(combined, byte(len(realCiphertext)>>8), byte(len(realCiphertext)))
		combined = append(combined, realCiphertext...)
		combined = append(combined, byte(len(decoyCiphertext)>>8), byte(len(decoyCiphertext)))
		combined = append(combined, decoyCiphertext...)

		result.Ciphertext = combined
		result.DecoyKey = decoyKey
	} else {
		// No decoy - simple format
		// [version (1)] [flags (1)] [len (2)] [ciphertext]
		combined := make([]byte, 0, 4+len(realCiphertext))
		combined = append(combined, Version)
		combined = append(combined, 0x00) // Flag: no decoy
		combined = append(combined, byte(len(realCiphertext)>>8), byte(len(realCiphertext)))
		combined = append(combined, realCiphertext...)

		result.Ciphertext = combined
	}

	return result, nil
}

// Decrypt decrypts a deniable ciphertext with the given key.
// Returns the decrypted message and whether a decoy key was used.
func (d *DeniableEncryptor) Decrypt(ciphertext, key []byte) (string, bool, error) {
	if len(ciphertext) < HeaderSize {
		return "", false, ErrInvalidCiphertext
	}

	version := ciphertext[0]
	if version != Version {
		return "", false, fmt.Errorf("unsupported version: %d", version)
	}

	flags := ciphertext[1]
	hasDecoy := flags&0x01 != 0

	realLen := int(ciphertext[2])<<8 | int(ciphertext[3])
	if len(ciphertext) < HeaderSize+realLen {
		return "", false, ErrInvalidCiphertext
	}

	realCiphertext := ciphertext[HeaderSize : HeaderSize+realLen]

	// Try to decrypt as real message first
	plaintext, err := crypto.DecryptWithKey(key, realCiphertext)
	if err == nil {
		// Successfully decrypted real message
		return string(unpadMessage(plaintext)), false, nil
	}

	// If there's a decoy and real decryption failed, try decoy path
	if hasDecoy {
		offset := HeaderSize + realLen
		if len(ciphertext) < offset+2 {
			return "", false, ErrInvalidCiphertext
		}

		decoyLen := int(ciphertext[offset])<<8 | int(ciphertext[offset+1])
		offset += 2

		if len(ciphertext) < offset+decoyLen {
			return "", false, ErrInvalidCiphertext
		}

		decoyCiphertext := ciphertext[offset : offset+decoyLen]

		// Try to decrypt the decoy ciphertext with the given key
		plaintext, err := crypto.DecryptWithKey(key, decoyCiphertext)
		if err == nil {
			return string(unpadMessage(plaintext)), true, nil
		}
	}

	return "", false, ErrDecryptionFailed
}

// DecryptWithKeys tries to decrypt using multiple keys and returns which key worked.
func (d *DeniableEncryptor) DecryptWithKeys(ciphertext []byte, keys [][]byte) (string, int, error) {
	for i, key := range keys {
		msg, _, err := d.Decrypt(ciphertext, key)
		if err == nil {
			return msg, i, nil
		}
	}
	return "", -1, ErrDecryptionFailed
}

// Helper functions

func padMessage(msg []byte, targetLen int) []byte {
	if len(msg) >= targetLen {
		// Add length prefix
		result := make([]byte, 2+len(msg))
		binary.BigEndian.PutUint16(result[:2], uint16(len(msg)))
		copy(result[2:], msg)
		return result
	}

	// Pad to target length
	padded := make([]byte, 2+targetLen)
	binary.BigEndian.PutUint16(padded[:2], uint16(len(msg)))
	copy(padded[2:], msg)

	// Fill remaining with random bytes
	if _, err := rand.Read(padded[2+len(msg):]); err != nil {
		// Fallback to zeros if random fails
		for i := 2 + len(msg); i < len(padded); i++ {
			padded[i] = 0
		}
	}

	return padded
}

func unpadMessage(padded []byte) []byte {
	if len(padded) < 2 {
		return padded
	}

	msgLen := binary.BigEndian.Uint16(padded[:2])
	if int(msgLen) > len(padded)-2 {
		return padded[2:]
	}

	return padded[2 : 2+msgLen]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
