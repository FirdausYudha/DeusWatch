package respond

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func reasonsDSN() string {
	if d := os.Getenv("STORE_DSN"); d != "" {
		return d
	}
	return "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"
}

// TestAppendReasonAccumulates guards the banlist "REASON" column the operator asked for: when the
// same IP keeps hitting different rules, the OPEN action's reason must accumulate the distinct rule
// names ("Failed SSH Login as root, SSH Login Attempt for Invalid User, WAF SQLi Block") instead of
// only showing the first one that fired. Case-insensitive dedup keeps repeats out. A second appendof
// an already-listed reason is a no-op.
func TestAppendReasonAccumulates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, reasonsDSN())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	s := NewStore(pool)

	ip := "203.0.113.211"
	defer pool.Exec(ctx, `DELETE FROM response_actions WHERE source_ip = $1::inet`, ip)
	_, _ = pool.Exec(ctx, `DELETE FROM response_actions WHERE source_ip = $1::inet`, ip)

	first := &Action{
		SourceIP: ip, ActionType: "block", Reason: "Failed SSH Login as root",
		BanSeconds: 600, OffenseCount: 1, Source: "playbook", Status: StatusRecommended,
	}
	if _, err := s.Insert(ctx, first); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Append two new distinct reasons + one dup of the first.
	for _, r := range []string{
		"SSH Login Attempt for Invalid User",
		"WAF SQLi Block",
		"failed ssh login as root", // dup, different casing — must NOT be re-added
	} {
		if err := s.AppendReason(ctx, ip, r); err != nil {
			t.Fatalf("append %q: %v", r, err)
		}
	}

	var got string
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(reason,'') FROM response_actions WHERE source_ip = $1::inet`, ip).Scan(&got); err != nil {
		t.Fatalf("read reason: %v", err)
	}
	want := "Failed SSH Login as root, SSH Login Attempt for Invalid User, WAF SQLi Block"
	if got != want {
		t.Fatalf("accumulated reason wrong\n got %q\nwant %q", got, want)
	}
	// Also confirm order-preserving: the first reason keeps its position.
	if !strings.HasPrefix(got, "Failed SSH Login as root, ") {
		t.Fatalf("reason should keep initial rule first, got %q", got)
	}
}
