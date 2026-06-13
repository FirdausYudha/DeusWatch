// Package auth menyediakan autentikasi (Argon2id), RBAC, sesi, dan audit log
// untuk DeusWatch (design doc bagian 4).
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameter Argon2id. Disetel wajar untuk server; dapat dinaikkan seiring hardware.
const (
	argonTime    = 2
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrMismatch dikembalikan saat password tidak cocok.
var ErrMismatch = errors.New("auth: password tidak cocok")

// HashPassword mengembalikan hash Argon2id ber-encoding standar
// ($argon2id$v=19$m=...,t=...,p=...$salt$hash).
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: baca salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword membandingkan password dengan hash ber-encoding (konstan-waktu).
func VerifyPassword(password, encoded string) error {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return fmt.Errorf("auth: format hash tidak valid")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return fmt.Errorf("auth: versi argon2 tidak didukung")
	}
	var mem uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &threads); err != nil {
		return fmt.Errorf("auth: parameter argon2 tidak valid")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("auth: salt tidak valid")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("auth: hash tidak valid")
	}

	got := argon2.IDKey([]byte(password), salt, time, mem, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}
