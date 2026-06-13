// Package migrate adalah runner migrasi SQL in-house (tanpa dependensi golang-migrate).
//
// Migrasi disematkan via package migrations (embed.FS). Versi yang sudah diterapkan
// dicatat di tabel schema_migrations; tiap berkas *.up.sql dijalankan dalam transaksi
// dan hanya sekali. Semua migrasi DeusWatch idempotent (IF NOT EXISTS / OR REPLACE),
// sehingga aman dijalankan ulang terhadap DB yang sudah dimigrasi manual.
package migrate

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Apply menjalankan semua migrasi *.up.sql dari fsys yang belum tercatat di
// schema_migrations, terurut menurut nama berkas. Mengembalikan jumlah migrasi
// yang baru diterapkan.
func Apply(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) (int, error) {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("migrate: buat schema_migrations: %w", err)
	}

	applied, err := appliedVersions(ctx, pool)
	if err != nil {
		return 0, err
	}

	files, err := upFiles(fsys)
	if err != nil {
		return 0, err
	}

	n := 0
	for _, f := range files {
		version := versionOf(f)
		if applied[version] {
			continue
		}
		sqlText, err := fs.ReadFile(fsys, f)
		if err != nil {
			return n, fmt.Errorf("migrate: baca %s: %w", f, err)
		}
		if err := applyOne(ctx, pool, version, string(sqlText)); err != nil {
			return n, fmt.Errorf("migrate: %s: %w", f, err)
		}
		n++
	}
	return n, nil
}

func applyOne(ctx context.Context, pool *pgxpool.Pool, version, sqlText string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, sqlText); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)
		ON CONFLICT (version) DO NOTHING`, version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func appliedVersions(ctx context.Context, pool *pgxpool.Pool) (map[string]bool, error) {
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("migrate: baca versi: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func upFiles(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("migrate: baca dir: %w", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}

// versionOf mengambil prefix versi dari nama berkas (mis. "000001_init_dcs.up.sql" -> "000001").
func versionOf(name string) string {
	if i := strings.IndexByte(name, '_'); i > 0 {
		return name[:i]
	}
	return name
}
