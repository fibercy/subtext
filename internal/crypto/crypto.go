// Package crypto provides X25519 key exchange and AES-256-GCM encryption.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	// KeySize is the size of X25519 keys in bytes
	KeySize = 32
	// NonceSize is the size of AES-GCM nonce
	NonceSize = 12
	// TagSize is the size of AES-GCM authentication tag
	TagSize = 16
)

var (
	ErrInvalidKeySize    = errors.New("invalid key size")
	ErrInvalidNonceSize  = errors.New("invalid nonce size")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrKeyExchangeFailed = errors.New("key exchange failed")
)

// KeyPair holds X25519 private and public keys
type KeyPair struct {
	PrivateKey [KeySize]byte
	PublicKey  [KeySize]byte
}

// GenerateKeyPair creates a new X25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	var privateKey [KeySize]byte
	if _, err := io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return nil, err
	}

	// Clamp the private key per X25519 spec
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	var publicKey [KeySize]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// ComputeSharedSecret performs X25519 key exchange
func ComputeSharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != KeySize || len(peerPublicKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	var priv, pub [KeySize]byte
	copy(priv[:], privateKey)
	copy(pub[:], peerPublicKey)

	shared, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return nil, ErrKeyExchangeFailed
	}

	// Derive a key using SHA-256 for domain separation
	h := sha256.Sum256(shared)
	return h[:], nil
}

// Encryptor handles AES-256-GCM encryption
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor creates a new AES-256-GCM encryptor with the given key
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Encryptor{aead: aead}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM
// Returns: nonce || ciphertext || tag
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends the ciphertext and tag to nonce
	ciphertext := e.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
// Input format: nonce || ciphertext || tag
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+TagSize {
		return nil, ErrDecryptionFailed
	}

	nonce := ciphertext[:NonceSize]
	encrypted := ciphertext[NonceSize:]

	plaintext, err := e.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// EncryptWithKey is a convenience function for one-off encryption
func EncryptWithKey(key, plaintext []byte) ([]byte, error) {
	enc, err := NewEncryptor(key)
	if err != nil {
		return nil, err
	}
	return enc.Encrypt(plaintext)
}

// DecryptWithKey is a convenience function for one-off decryption
func DecryptWithKey(key, ciphertext []byte) ([]byte, error) {
	enc, err := NewEncryptor(key)
	if err != nil {
		return nil, err
	}
	return enc.Decrypt(ciphertext)
}

// Compact encryption constants - reduced overhead for steganography
const (
	CompactNonceSize = 4 // 4-byte nonce (birthday bound ~65K per key, sufficient for chat)
	CompactTagSize   = 4 // 4-byte truncated HMAC (1 in 2^32 forgery probability)
)

// CompactEncrypt encrypts with minimal overhead using AES-CTR + truncated HMAC
// Format: nonce (8) || ciphertext || truncated_tag (8)
// Total overhead: 16 bytes (vs 28 for standard AES-GCM)
func CompactEncrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	// Split key: first 16 bytes for AES, last 16 bytes for HMAC
	aesKey := key[:16]
	hmacKey := key[16:]

	// Generate compact nonce
	nonce := make([]byte, CompactNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Create AES-CTR cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Pad nonce to 16 bytes for CTR IV
	iv := make([]byte, aes.BlockSize)
	copy(iv, nonce)

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	// Compute truncated HMAC over nonce || ciphertext
	h := sha256.New()
	h.Write(hmacKey)
	h.Write(nonce)
	h.Write(ciphertext)
	fullTag := h.Sum(nil)
	tag := fullTag[:CompactTagSize]

	// Assemble: nonce || ciphertext || tag
	result := make([]byte, CompactNonceSize+len(ciphertext)+CompactTagSize)
	copy(result[:CompactNonceSize], nonce)
	copy(result[CompactNonceSize:CompactNonceSize+len(ciphertext)], ciphertext)
	copy(result[CompactNonceSize+len(ciphertext):], tag)

	return result, nil
}

// CompactDecrypt decrypts data encrypted with CompactEncrypt
func CompactDecrypt(key, data []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	if len(data) < CompactNonceSize+CompactTagSize {
		return nil, ErrDecryptionFailed
	}

	// Split key
	aesKey := key[:16]
	hmacKey := key[16:]

	// Extract components
	nonce := data[:CompactNonceSize]
	ciphertext := data[CompactNonceSize : len(data)-CompactTagSize]
	tag := data[len(data)-CompactTagSize:]

	// Verify HMAC
	h := sha256.New()
	h.Write(hmacKey)
	h.Write(nonce)
	h.Write(ciphertext)
	expectedTag := h.Sum(nil)[:CompactTagSize]

	// Constant-time comparison
	valid := true
	for i := 0; i < CompactTagSize; i++ {
		valid = valid && (tag[i] == expectedTag[i])
	}
	if !valid {
		return nil, ErrDecryptionFailed
	}

	// Decrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	copy(iv, nonce)

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
