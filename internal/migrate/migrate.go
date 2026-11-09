// Package migrate is an in-house SQL migration runner (no golang-migrate dependency).
//
// Migrations are embedded via the migrations package (embed.FS). Applied versions are
// recorded in the schema_migrations table; each *.up.sql file runs inside a transaction
// and only once. All DeusWatch migrations are idempotent (IF NOT EXISTS / OR REPLACE),
// so they are safe to re-run against a DB that was migrated manually.
package migrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Apply runs all *.up.sql migrations from fsys that are not yet recorded in
// schema_migrations, ordered by file name. Returns the number of newly applied
// migrations.
func Apply(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) (int, error) {
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("migrate: create schema_migrations: %w", err)
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
			return n, fmt.Errorf("migrate: read %s: %w", f, err)
		}
		if err := applyWithRetry(ctx, pool, version, string(sqlText)); err != nil {
			return n, fmt.Errorf("migrate: %s: %w", f, err)
		}
		n++
	}
	return n, nil
}

// applyWithRetry runs one migration, retrying on a transient serialization/deadlock error
// (40P01 deadlock_detected / 40001 serialization_failure). On a busy server a migration that must
// take a table-level lock - e.g. ALTER TABLE ADD COLUMN on the hot events hypertable - can deadlock
// with concurrent ingestion. The deadlock is transient: a short backoff and retry almost always
// succeeds, whereas a hard failure stops the runner and leaves every LATER migration unapplied too.
func applyWithRetry(ctx context.Context, pool *pgxpool.Pool, version, sqlText string) error {
	const maxAttempts = 6
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err = applyOne(ctx, pool, version, sqlText); err == nil || !isTransientLockErr(err) {
			return err
		}
		backoff := time.Duration(attempt) * 250 * time.Millisecond
		log.Printf("migrate: %s hit a transient DB lock (%v); retry %d/%d in %s",
			version, err, attempt, maxAttempts, backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return err
}

// isTransientLockErr reports whether a Postgres error is a deadlock or serialization failure, which
// are safe to retry (the migration's transaction was rolled back, nothing was recorded).
func isTransientLockErr(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "40P01" || pgErr.Code == "40001"
	}
	return false
}

func applyOne(ctx context.Context, pool *pgxpool.Pool, version, sqlText string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Run every migration with the RLS super-admin bypass, LOCAL to this transaction (auto-reset on
	// commit/rollback, so it never leaks to other borrowers of a shared pool). Migration 000050
	// FORCEs row-level security, which applies even to the table owner, so without this a future
	// data migration that touches a tenant-scoped table would be silently row-filtered. DDL is not
	// row-filtered, so this is a no-op for pure-schema migrations and correct insurance for data ones.
	if _, err := tx.Exec(ctx, `SET LOCAL deuswatch.superadmin = '1'`); err != nil {
		return err
	}
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
		return nil, fmt.Errorf("migrate: read versions: %w", err)
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
		return nil, fmt.Errorf("migrate: read dir: %w", err)
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

// versionOf extracts the version prefix from a file name (e.g. "000001_init_dcs.up.sql" -> "000001").
func versionOf(name string) string {
	if i := strings.IndexByte(name, '_'); i > 0 {
		return name[:i]
	}
	return name
}
