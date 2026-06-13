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
			t.Errorf("versionOf(%q)=%q, mau %q", in, got, want)
		}
	}
}

func TestUpFilesSortedAndFiltered(t *testing.T) {
	files, err := upFiles(migrations.FS)
	if err != nil {
		t.Fatalf("upFiles: %v", err)
	}
	if len(files) < 6 {
		t.Fatalf("harap >=6 migrasi up, dapat %d", len(files))
	}
	for i := 1; i < len(files); i++ {
		if files[i-1] > files[i] {
			t.Fatalf("berkas tak terurut: %v", files)
		}
	}
	for _, f := range files {
		if len(f) < 7 || f[len(f)-7:] != ".up.sql" {
			t.Fatalf("berkas non-up bocor: %q", f)
		}
	}
}

// TestApplyIdempotent: terhadap DB nyata, Apply kedua tak menerapkan apa-apa.
func TestApplyIdempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres tak tersedia: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("Postgres tak tersedia: %v", err)
	}

	if _, err := Apply(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("Apply pertama: %v", err)
	}
	n, err := Apply(ctx, pool, migrations.FS)
	if err != nil {
		t.Fatalf("Apply kedua: %v", err)
	}
	if n != 0 {
		t.Fatalf("Apply kedua menerapkan %d migrasi, mau 0 (idempotent)", n)
	}
}
