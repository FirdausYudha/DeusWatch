package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func dsn() string {
	if d := os.Getenv("STORE_DSN"); d != "" {
		return d
	}
	return "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"
}

func TestStoreLoginSession(t *testing.T) {
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
	username := fmt.Sprintf("test-%d", time.Now().UnixNano())
	defer pool.Exec(ctx, `DELETE FROM users WHERE username=$1`, username) // cascade hapus sesi

	if err := s.CreateUser(ctx, username, "rahasia123", RoleAnalyst); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	u, token, err := s.Login(ctx, username, "rahasia123", time.Hour)
	if err != nil {
		t.Fatalf("Login benar seharusnya sukses: %v", err)
	}
	if u.Role != RoleAnalyst {
		t.Fatalf("role salah: %q", u.Role)
	}

	got, err := s.SessionUser(ctx, token)
	if err != nil || got.Username != username {
		t.Fatalf("SessionUser dengan token valid gagal: %v / %+v", err, got)
	}

	// Password salah -> ErrAuth.
	if _, _, err := s.Login(ctx, username, "salah", time.Hour); !errors.Is(err, ErrAuth) {
		t.Fatalf("password salah harus ErrAuth, dapat: %v", err)
	}
	// Token ngawur -> ErrAuth.
	if _, err := s.SessionUser(ctx, "deadbeef"); !errors.Is(err, ErrAuth) {
		t.Fatalf("token invalid harus ErrAuth, dapat: %v", err)
	}
	// Logout -> token tak lagi valid.
	if err := s.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := s.SessionUser(ctx, token); !errors.Is(err, ErrAuth) {
		t.Fatalf("token setelah logout harus ErrAuth, dapat: %v", err)
	}
	t.Logf("OK: create->login->session->logout untuk %s", username)
}
