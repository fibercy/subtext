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
