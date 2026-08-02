// Package tenant provides org-scoped helpers for tenancy features.
package tenant

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext using AES-GCM with the given key.
// The key must be 32 bytes (AES-256). Returns base64 ciphertext.
func Encrypt(key []byte, plaintext string) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("secrets: key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("secrets: cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("secrets: gcm: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("secrets: nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded AES-GCM ciphertext with the given key.
func Decrypt(key []byte, b64ciphertext string) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("secrets: key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("secrets: cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("secrets: gcm: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(b64ciphertext)
	if err != nil {
		return "", fmt.Errorf("secrets: decode: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("secrets: ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("secrets: decrypt: %w", err)
	}

	return string(plaintext), nil
}

// PadKey pads or truncates a key to 32 bytes for AES-256.
// Used for BC_SECRET_KEY which may not be exactly 32 bytes.
func PadKey(key string) []byte {
	plain := []byte(key)
	if len(plain) >= 32 {
		return plain[:32]
	}
	padded := make([]byte, 32)
	copy(padded, plain)
	return padded
}
