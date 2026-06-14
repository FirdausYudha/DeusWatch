package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
)

func TestTOTPGenerateValidate(t *testing.T) {
	secret, url, err := GenerateTOTPSecret("alice")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if secret == "" || url == "" {
		t.Fatal("secret/otpauth URL empty")
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !ValidateTOTP(secret, code) {
		t.Fatal("the current TOTP code should be valid")
	}
	// A code from 1970 is far outside the window -> invalid.
	old, _ := totp.GenerateCode(secret, time.Unix(0, 0))
	if ValidateTOTP(secret, old) {
		t.Fatal("an old TOTP code (1970) must not be valid now")
	}
}

func Test2FALoginFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	s := NewStore(pool)
	username := fmt.Sprintf("test2fa-%d", time.Now().UnixNano())
	defer pool.Exec(ctx, `DELETE FROM users WHERE username=$1`, username)

	if err := s.CreateUser(ctx, username, "secret123", RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	var id string
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE username=$1`, username).Scan(&id); err != nil {
		t.Fatalf("fetch id: %v", err)
	}

	secret, _, _ := GenerateTOTPSecret(username)
	if err := s.SetTOTPSecret(ctx, id, secret); err != nil {
		t.Fatalf("SetTOTPSecret: %v", err)
	}

	// No code -> Err2FARequired.
	if _, _, err := s.Login(ctx, username, "secret123", "", time.Hour); !errors.Is(err, Err2FARequired) {
		t.Fatalf("login without a code must be Err2FARequired, got: %v", err)
	}
	// Wrong code -> ErrAuth.
	if _, _, err := s.Login(ctx, username, "secret123", "000000", time.Hour); err == nil {
		t.Fatal("login with a wrong code should fail")
	}
	// Valid code -> success.
	code, _ := totp.GenerateCode(secret, time.Now())
	if _, tok, err := s.Login(ctx, username, "secret123", code, time.Hour); err != nil || tok == "" {
		t.Fatalf("login with a valid code should succeed: %v", err)
	}
	t.Logf("OK: 2FA login flow (no code->required, wrong->fail, valid->success) for %s", username)
}
