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
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	s := NewStore(pool)
	username := fmt.Sprintf("test-%d", time.Now().UnixNano())
	defer pool.Exec(ctx, `DELETE FROM users WHERE username=$1`, username) // cascade-deletes sessions

	if err := s.CreateUser(ctx, username, "secret123", RoleAnalyst, nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	u, token, err := s.Login(ctx, username, "secret123", "", time.Hour)
	if err != nil {
		t.Fatalf("correct Login should succeed: %v", err)
	}
	if u.Role != RoleAnalyst {
		t.Fatalf("wrong role: %q", u.Role)
	}

	got, err := s.SessionUser(ctx, token)
	if err != nil || got.Username != username {
		t.Fatalf("SessionUser with a valid token failed: %v / %+v", err, got)
	}

	// Wrong password -> ErrAuth.
	if _, _, err := s.Login(ctx, username, "wrong", "", time.Hour); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong password must be ErrAuth, got: %v", err)
	}
	// Garbage token -> ErrAuth.
	if _, err := s.SessionUser(ctx, "deadbeef"); !errors.Is(err, ErrAuth) {
		t.Fatalf("invalid token must be ErrAuth, got: %v", err)
	}
	// Logout -> token no longer valid.
	if err := s.Logout(ctx, token); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := s.SessionUser(ctx, token); !errors.Is(err, ErrAuth) {
		t.Fatalf("token after logout must be ErrAuth, got: %v", err)
	}
	t.Logf("OK: create->login->session->logout for %s", username)
}
