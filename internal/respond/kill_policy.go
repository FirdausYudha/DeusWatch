package respond

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// KillPolicy configures the auto-kill behaviour (docs/auto-kill.md). Fail-closed defaults:
// auto_approve=false, no whitelist entries removed, rate limit at 3/min.
type KillPolicy struct {
	AutoApprove     bool     `json:"auto_approve"`
	Whitelist       []string `json:"whitelist"`
	RateLimitPerMin int      `json:"rate_limit_per_min"`
}

// DefaultKillPolicy is what a brand-new install effectively sees before the migration seeds row 1
// (and what the engine falls back to when the DB row can't be read). Recommend-only, sane
// whitelist, conservative rate limit.
func DefaultKillPolicy() KillPolicy {
	return KillPolicy{
		AutoApprove: false,
		Whitelist: []string{
			"systemd", "init", "sshd", "dockerd", "containerd",
			"postgres", "mysqld", "nginx", "apache2", "nats-server",
			"deuswatch-agent", "deuswatch-worker", "deuswatch-api", "deuswatch-gateway",
		},
		RateLimitPerMin: 3,
	}
}

// LoadKillPolicy reads the singleton row. Missing table or missing row → the fail-closed default,
// not an error — otherwise a fresh install or a rollback would fatal the worker at boot.
func (s *Store) LoadKillPolicy(ctx context.Context) (KillPolicy, error) {
	p := DefaultKillPolicy()
	err := s.pool.QueryRow(ctx,
		`SELECT auto_approve, whitelist, rate_limit_per_min FROM kill_policy WHERE id = 1`).
		Scan(&p.AutoApprove, &p.Whitelist, &p.RateLimitPerMin)
	if err != nil {
		if isNoRowsOrRelation(err) {
			return DefaultKillPolicy(), nil
		}
		return DefaultKillPolicy(), fmt.Errorf("respond: load kill policy: %w", err)
	}
	return p, nil
}

// SaveKillPolicy replaces the singleton row. Validates that at least one whitelist entry survives
// (an admin who wipes the list is one bad rule away from killing sshd) and clamps the rate limit
// into the CHECK-constraint range so we surface the friendly error instead of a Postgres one.
func (s *Store) SaveKillPolicy(ctx context.Context, p KillPolicy) error {
	wl := normaliseWhitelist(p.Whitelist)
	if len(wl) == 0 {
		return fmt.Errorf("kill whitelist may not be empty (would allow auto-killing sshd/systemd)")
	}
	if p.RateLimitPerMin < 1 || p.RateLimitPerMin > 60 {
		return fmt.Errorf("rate_limit_per_min must be between 1 and 60, got %d", p.RateLimitPerMin)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO kill_policy (id, auto_approve, whitelist, rate_limit_per_min, updated_at)
		VALUES (1, $1, $2, $3, now())
		ON CONFLICT (id) DO UPDATE SET
		  auto_approve = EXCLUDED.auto_approve,
		  whitelist = EXCLUDED.whitelist,
		  rate_limit_per_min = EXCLUDED.rate_limit_per_min,
		  updated_at = now()`,
		p.AutoApprove, wl, p.RateLimitPerMin)
	if err != nil {
		return fmt.Errorf("respond: save kill policy: %w", err)
	}
	return nil
}

// normaliseWhitelist trims + lowercases + dedups + sorts entries so the stored order is stable and
// the case-insensitive match downstream is a plain string compare.
func normaliseWhitelist(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// isNoRowsOrRelation reports whether err is either "no rows" (empty table) or "relation does not
// exist" (migration not applied yet). Both mean "fall back to the default policy", not "fatal".
func isNoRowsOrRelation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no rows") || strings.Contains(msg, "does not exist")
}
