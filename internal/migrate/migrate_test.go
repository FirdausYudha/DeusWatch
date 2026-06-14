package migrate

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"deuswatch/migrations"
)

func dsn() string {
	if d := os.Getenv("STORE_DSN"); d != "" {
		return d
	}
	return "postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable"
}

func TestVersionOf(t *testing.T) {
	cases := map[string]string{
		"000001_init_dcs.up.sql":         "000001",
		"000006_response_actions.up.sql": "000006",
		"weird.sql":                      "weird.sql",
	}
	for in, want := range cases {
		if got := versionOf(in); got != want {
			t.Errorf("versionOf(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestUpFilesSortedAndFiltered(t *testing.T) {
	files, err := upFiles(migrations.FS)
	if err != nil {
		t.Fatalf("upFiles: %v", err)
	}
	if len(files) < 6 {
		t.Fatalf("expected >=6 up migrations, got %d", len(files))
	}
	for i := 1; i < len(files); i++ {
		if files[i-1] > files[i] {
			t.Fatalf("files not sorted: %v", files)
		}
	}
	for _, f := range files {
		if len(f) < 7 || f[len(f)-7:] != ".up.sql" {
			t.Fatalf("non-up file leaked: %q", f)
		}
	}
}

// TestApplyIdempotent: against a real DB, the second Apply applies nothing.
func TestApplyIdempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	if _, err := Apply(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	n, err := Apply(ctx, pool, migrations.FS)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if n != 0 {
		t.Fatalf("second Apply applied %d migrations, want 0 (idempotent)", n)
	}
}
