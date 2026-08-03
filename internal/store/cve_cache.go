package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CVEPriorityCache is the persistent lookup the worker uses to enrich USN advisories with the
// per-CVE Ubuntu priority (docs/vulnerability-va.md; migration 000058). Ubuntu's notices feed
// carries no severity, so the worker fetches each CVE's `priority` from ubuntu.com/security/<CVE>.json
// once and stashes it here — subsequent feed refreshes hit the DB, not the network.

// GetCVEPriority returns (priority, hit, error). A cache hit yields hit=true and the stored
// priority (which may legitimately be "" when Ubuntu doesn't publish one for that CVE — we still
// want to remember that "" is the answer, so the worker doesn't retry every refresh). Expired rows
// count as a miss.
func (s *Store) GetCVEPriority(ctx context.Context, cve string) (string, bool, error) {
	var priority string
	err := s.q(ctx).QueryRow(ctx,
		`SELECT priority FROM cve_priority_cache WHERE cve = $1 AND expires_at > now()`,
		cve).Scan(&priority)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: get cve priority %s: %w", cve, err)
	}
	return priority, true, nil
}

// PutCVEPriority upserts a CVE's priority with the given TTL. A ttl<=0 means "cache indefinitely"
// (30 years from now — priorities almost never change in practice, and the row can be re-fetched
// via a manual DELETE if it ever does).
func (s *Store) PutCVEPriority(ctx context.Context, cve, priority string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 30 * 365 * 24 * time.Hour
	}
	expires := time.Now().Add(ttl)
	_, err := s.q(ctx).Exec(ctx, `
		INSERT INTO cve_priority_cache (cve, priority, checked_at, expires_at)
		VALUES ($1, $2, now(), $3)
		ON CONFLICT (cve) DO UPDATE SET
		  priority = EXCLUDED.priority,
		  checked_at = now(),
		  expires_at = EXCLUDED.expires_at`, cve, priority, expires)
	if err != nil {
		return fmt.Errorf("store: put cve priority %s: %w", cve, err)
	}
	return nil
}
