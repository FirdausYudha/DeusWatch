package auth

import (
	"errors"
	"strconv"
	"strings"
)

// minPasswordLen is the policy floor for NEW passwords (register, create user,
// change password). Seeded accounts (dev admin) are not re-validated, so raising
// this never locks an existing deployment out. Override via SetMinPasswordLen
// (PASSWORD_MIN_LEN in cmd/api).
var minPasswordLen = 8

// SetMinPasswordLen overrides the minimum new-password length (values < 8 are
// clamped to 8 - the policy is a floor, not a knob to weaken).
func SetMinPasswordLen(n int) {
	if n < 8 {
		n = 8
	}
	minPasswordLen = n
}

// commonPasswords are rejected outright regardless of length. Deliberately tiny:
// just the guesses every SSH/web brute-force list tries first (the events this
// very platform detects all day).
var commonPasswords = map[string]struct{}{
	"password": {}, "password1": {}, "password123": {}, "passw0rd": {},
	"12345678": {}, "123456789": {}, "1234567890": {}, "qwertyuiop": {},
	"qwerty123": {}, "letmein1": {}, "iloveyou": {}, "sunshine": {},
	"admin123": {}, "administrator": {}, "welcome1": {}, "changeme": {},
	"deuswatch": {}, "thewatcher": {},
}

// ValidatePassword enforces the new-password policy: minimum length, not a
// top-list password, not the username, not one repeated character.
func ValidatePassword(username, password string) error {
	if len(password) < minPasswordLen {
		return errors.New("password must be at least " + strconv.Itoa(minPasswordLen) + " characters")
	}
	lower := strings.ToLower(password)
	if _, bad := commonPasswords[lower]; bad {
		return errors.New("password is too common - pick something less guessable")
	}
	if username != "" && lower == strings.ToLower(username) {
		return errors.New("password must not be the same as the username")
	}
	if allSameRune(password) {
		return errors.New("password must not be a single repeated character")
	}
	return nil
}

func allSameRune(s string) bool {
	var first rune
	for i, r := range s {
		if i == 0 {
			first = r
		} else if r != first {
			return false
		}
	}
	return true
}
