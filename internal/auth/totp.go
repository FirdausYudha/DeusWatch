package auth

import (
	"github.com/pquerna/otp/totp"
)

// totpIssuer appears in authenticator apps (Google Authenticator, etc.).
const totpIssuer = "DeusWatch"

// GenerateTOTPSecret creates a new TOTP secret for the username. Returns the
// base32 secret and the otpauth:// URI (for QR / manual entry in an authenticator).
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

// ValidateTOTP verifies a 6-digit code against the secret (±1 step skew tolerance).
func ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}
