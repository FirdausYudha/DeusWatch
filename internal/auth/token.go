package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// newToken generates a random session token (256-bit) along with its SHA-256 hash.
// The raw token is sent to the client; ONLY the hash is stored in the database.
func newToken() (raw, hash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	raw = hex.EncodeToString(b)
	return raw, hashToken(raw)
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
