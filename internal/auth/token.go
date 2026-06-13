package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

// newToken menghasilkan token sesi acak (256-bit) beserta hash SHA-256-nya.
// Token mentah dikirim ke client; HANYA hash yang disimpan di database.
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
