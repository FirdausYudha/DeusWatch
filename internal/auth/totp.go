package auth

import (
	"github.com/pquerna/otp/totp"
)

// totpIssuer muncul di aplikasi authenticator (Google Authenticator, dll.).
const totpIssuer = "DeusWatch"

// GenerateTOTPSecret membuat secret TOTP baru untuk username. Mengembalikan
// secret base32 dan URI otpauth:// (untuk QR / entri manual di authenticator).
func GenerateTOTPSecret(username string) (secret, otpauthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ValidateTOTP memverifikasi kode 6-digit terhadap secret (toleransi skew ±1 langkah).
func ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}
