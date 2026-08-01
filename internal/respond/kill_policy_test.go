package respond

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func killPolicyDSN() string {
	if d := os.Getenv("STORE_DSN"); d != "" {
		return d
	}
	return "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"
}

// TestKillPolicyLoadAndSave is the round trip against the real DB: load the default (migration
// 000057 seeded row 1), flip a value, save, read back, confirm every field survived. Also
// exercises the whitelist normalisation so callers can't accidentally save "  SSHD  " and then
// fail case-sensitive matching later.
func TestKillPolicyLoadAndSave(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, killPolicyDSN())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	s := NewStore(pool)

	// Load the seeded default so we can restore it at the end (test isolation).
	initial, err := s.LoadKillPolicy(ctx)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	defer func() {
		if err := s.SaveKillPolicy(ctx, initial); err != nil {
			t.Logf("restore initial policy: %v", err)
		}
	}()

	// Save a modified policy with intentionally messy whitelist input.
	changed := KillPolicy{
		AutoApprove:     true,
		Whitelist:       []string{"  SSHD  ", "sshd", "", "systemd", "custom-daemon"},
		RateLimitPerMin: 7,
	}
	if err := s.SaveKillPolicy(ctx, changed); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.LoadKillPolicy(ctx)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !got.AutoApprove || got.RateLimitPerMin != 7 {
		t.Fatalf("scalar fields did not round-trip: %+v", got)
	}
	// After normalisation: dedup (case-insensitive), drop empty, lowercase, sort.
	want := []string{"custom-daemon", "sshd", "systemd"}
	if len(got.Whitelist) != len(want) {
		t.Fatalf("whitelist length: got %v, want %v", got.Whitelist, want)
	}
	for i := range want {
		if got.Whitelist[i] != want[i] {
			t.Fatalf("whitelist[%d]: got %q, want %q", i, got.Whitelist[i], want[i])
		}
	}
}

// TestKillPolicyValidatesEmptyWhitelist: an admin who nukes the whitelist would be one bad rule
// away from auto-killing sshd. Save must refuse.
func TestKillPolicyValidatesEmptyWhitelist(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, killPolicyDSN())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	s := NewStore(pool)
	err = s.SaveKillPolicy(ctx, KillPolicy{AutoApprove: true, Whitelist: []string{"  ", ""}, RateLimitPerMin: 3})
	if err == nil {
		t.Fatal("empty whitelist must be refused")
	}
}

// TestKillPolicyValidatesRateLimitRange: outside 1..60 must fail before it hits Postgres, so the
// error message is friendlier than a constraint violation.
func TestKillPolicyValidatesRateLimitRange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, killPolicyDSN())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	s := NewStore(pool)
	for _, bad := range []int{0, -1, 61, 1000} {
		p := DefaultKillPolicy()
		p.RateLimitPerMin = bad
		if err := s.SaveKillPolicy(ctx, p); err == nil {
			t.Fatalf("rate_limit_per_min=%d must be refused", bad)
		}
	}
}
