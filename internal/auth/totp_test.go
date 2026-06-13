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
		t.Fatal("secret/otpauth URL kosong")
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if !ValidateTOTP(secret, code) {
		t.Fatal("kode TOTP saat ini seharusnya valid")
	}
	// Kode dari 1970 jauh di luar jendela -> tidak valid.
	old, _ := totp.GenerateCode(secret, time.Unix(0, 0))
	if ValidateTOTP(secret, old) {
		t.Fatal("kode TOTP lama (1970) tidak boleh valid sekarang")
	}
}

func Test2FALoginFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres tak tersedia: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres tak tersedia: %v", err)
	}

	s := NewStore(pool)
	username := fmt.Sprintf("test2fa-%d", time.Now().UnixNano())
	defer pool.Exec(ctx, `DELETE FROM users WHERE username=$1`, username)

	if err := s.CreateUser(ctx, username, "rahasia123", RoleViewer); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	var id string
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE username=$1`, username).Scan(&id); err != nil {
		t.Fatalf("ambil id: %v", err)
	}

	secret, _, _ := GenerateTOTPSecret(username)
	if err := s.SetTOTPSecret(ctx, id, secret); err != nil {
		t.Fatalf("SetTOTPSecret: %v", err)
	}

	// Tanpa kode -> Err2FARequired.
	if _, _, err := s.Login(ctx, username, "rahasia123", "", time.Hour); !errors.Is(err, Err2FARequired) {
		t.Fatalf("login tanpa kode harus Err2FARequired, dapat: %v", err)
	}
	// Kode salah -> ErrAuth.
	if _, _, err := s.Login(ctx, username, "rahasia123", "000000", time.Hour); err == nil {
		t.Fatal("login kode salah seharusnya gagal")
	}
	// Kode valid -> sukses.
	code, _ := totp.GenerateCode(secret, time.Now())
	if _, tok, err := s.Login(ctx, username, "rahasia123", code, time.Hour); err != nil || tok == "" {
		t.Fatalf("login dengan kode valid seharusnya sukses: %v", err)
	}
	t.Logf("OK: alur login 2FA (tanpa kode->required, salah->gagal, valid->sukses) untuk %s", username)
}
