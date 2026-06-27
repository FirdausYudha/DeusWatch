package hashrep

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Cache is a TTL-bearing store of file-hash reputation results in Postgres
// (the file_hash_reputation table), mirroring the CTI cache.
type Cache struct {
	pool *pgxpool.Pool
}

func NewCache(pool *pgxpool.Pool) *Cache { return &Cache{pool: pool} }

// Get returns the cached indicator for a hash if present AND not expired.
func (c *Cache) Get(ctx context.Context, sha256 string) (Indicator, bool, error) {
	var ind Indicator
	var verdict string
	err := c.pool.QueryRow(ctx, `
		SELECT verdict, source, detail FROM file_hash_reputation
		WHERE sha256 = $1 AND expires_at > now()`, strings.ToLower(sha256)).
		Scan(&verdict, &ind.Source, &ind.Detail)
	if errors.Is(err, pgx.ErrNoRows) {
		return Indicator{}, false, nil
	}
	if err != nil {
		return Indicator{}, false, fmt.Errorf("hashrep: cache get: %w", err)
	}
	ind.Verdict = Verdict(verdict)
	return ind, true, nil
}

// Put stores/updates a hash indicator with a TTL. UPSERT resolves concurrent look-ups.
func (c *Cache) Put(ctx context.Context, sha256 string, ind Indicator, ttl time.Duration) error {
	_, err := c.pool.Exec(ctx, `
		INSERT INTO file_hash_reputation (sha256, verdict, source, detail, checked_at, expires_at)
		VALUES ($1, $2, $3, $4, now(), $5)
		ON CONFLICT (sha256) DO UPDATE SET
			verdict    = EXCLUDED.verdict,
			source     = EXCLUDED.source,
			detail     = EXCLUDED.detail,
			checked_at = now(),
			expires_at = EXCLUDED.expires_at`,
		strings.ToLower(sha256), string(ind.Verdict), ind.Source, ind.Detail, time.Now().Add(ttl))
	if err != nil {
		return fmt.Errorf("hashrep: cache put: %w", err)
	}
	return nil
}
