// Package secret provides authenticated encryption for secrets stored at rest
// (integration API keys, device credentials — design doc section 4, "Secrets").
//
// AES-256-GCM with a master key from the SECRETS_KEY environment variable. Encrypted
// values carry a version prefix so plaintext/legacy values pass through unchanged.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const prefix = "enc:v1:"

// Cipher encrypts and decrypts short secret values.
type Cipher struct{ aead cipher.AEAD }

// FromEnv builds a Cipher from SECRETS_KEY (base64 of 32 bytes). If SECRETS_KEY is
// unset it derives a deterministic development key (so restarts can still decrypt
// existing rows) and reports dev=true so the caller can warn.
func FromEnv() (c *Cipher, dev bool, err error) {
	raw := os.Getenv("SECRETS_KEY")
	var key []byte
	if raw == "" {
		sum := sha256.Sum256([]byte("deuswatch-dev-secrets-key"))
		key = sum[:]
		dev = true
	} else {
		b, derr := base64.StdEncoding.DecodeString(raw)
		if derr != nil || len(b) != 32 {
			return nil, false, fmt.Errorf("secret: SECRETS_KEY must be base64 of exactly 32 bytes")
		}
		key = b
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, dev, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, dev, err
	}
	return &Cipher{aead: aead}, dev, nil
}

// Encrypt returns a prefixed base64 token (nonce || ciphertext) for plaintext.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt. A value without the prefix is returned unchanged
// (so plaintext/legacy values are tolerated).
func (c *Cipher) Decrypt(token string) (string, error) {
	if !strings.HasPrefix(token, prefix) {
		return token, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(token, prefix))
	if err != nil {
		return "", err
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("secret: ciphertext too short")
	}
	pt, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// IsEncrypted reports whether v is one of our encryption tokens.
func IsEncrypted(v string) bool { return strings.HasPrefix(v, prefix) }
