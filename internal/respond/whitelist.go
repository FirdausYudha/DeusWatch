package respond

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// WhitelistEntry is one trusted IP/CIDR the response engine must never ban. `Kind` classifies the
// entry as `internal` (our own network — counts as "our side" for the INBOUND/OUTBOUND/LATERAL
// direction classifier) or `external` (a trusted third party — still not banned, but doesn't flip a
// source into LATERAL). Default: internal.
type WhitelistEntry struct {
	ID        string    `json:"id"`
	CIDR      string    `json:"cidr"`
	Note      string    `json:"note"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
}

// validKind returns k if it's `internal` or `external`, else "internal" (safe default).
func validKind(k string) string {
	k = strings.TrimSpace(strings.ToLower(k))
	if k == "external" {
		return "external"
	}
	return "internal"
}

// NormalizeCIDR validates a single IP or CIDR and returns its canonical CIDR form
// (a bare host becomes /32 or /128). Used to give clean errors before hitting the DB.
func NormalizeCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty IP/CIDR")
	}
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return ipnet.String(), nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("invalid IP or CIDR: %q", s)
	}
	if ip.To4() != nil {
		return ip.String() + "/32", nil
	}
	return ip.String() + "/128", nil
}

// ipInNets reports whether ipStr falls within any of the given networks.
func ipInNets(ipStr string, nets []*net.IPNet) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// ListWhitelist returns all whitelist entries (newest first).
func (s *Store) ListWhitelist(ctx context.Context) ([]WhitelistEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, cidr::text, note, kind, created_at FROM ip_whitelist ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("respond: list whitelist: %w", err)
	}
	defer rows.Close()
	out := make([]WhitelistEntry, 0, 16)
	for rows.Next() {
		var e WhitelistEntry
		if err := rows.Scan(&e.ID, &e.CIDR, &e.Note, &e.Kind, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddWhitelist inserts a trusted IP/CIDR (idempotent on the CIDR). kind is 'internal' (default) or
// 'external'; unknown/empty falls back to internal.
func (s *Store) AddWhitelist(ctx context.Context, cidr, note, kind string) (*WhitelistEntry, error) {
	norm, err := NormalizeCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var e WhitelistEntry
	err = s.pool.QueryRow(ctx,
		`INSERT INTO ip_whitelist (cidr, note, kind) VALUES ($1::cidr, $2, $3)
		 ON CONFLICT (cidr) DO UPDATE SET note = EXCLUDED.note, kind = EXCLUDED.kind
		 RETURNING id, cidr::text, note, kind, created_at`,
		norm, note, validKind(kind)).Scan(&e.ID, &e.CIDR, &e.Note, &e.Kind, &e.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("respond: add whitelist: %w", err)
	}
	return &e, nil
}

// DeleteWhitelist removes a whitelist entry by id.
func (s *Store) DeleteWhitelist(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM ip_whitelist WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("respond: delete whitelist: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("respond: whitelist entry not found")
	}
	return nil
}

// WhitelistNets loads the whitelist as parsed networks for the engine — every entry regardless of
// kind, because BOTH internal and external whitelist kinds mean "never ban" (that's the whole point
// of the whitelist).
func (s *Store) WhitelistNets(ctx context.Context) ([]*net.IPNet, error) {
	entries, err := s.ListWhitelist(ctx)
	if err != nil {
		return nil, err
	}
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		if _, n, err := net.ParseCIDR(e.CIDR); err == nil {
			nets = append(nets, n)
		}
	}
	return nets, nil
}

// WhitelistInternalNets returns ONLY the entries tagged `internal` — used by the direction
// classifier to decide whether an IP counts as "our side" for INBOUND/OUTBOUND/LATERAL tagging.
// Combined with the RFC1918 loopback nets by the caller so common private ranges are always internal.
func (s *Store) WhitelistInternalNets(ctx context.Context) ([]*net.IPNet, error) {
	entries, err := s.ListWhitelist(ctx)
	if err != nil {
		return nil, err
	}
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		if e.Kind != "internal" {
			continue
		}
		if _, n, err := net.ParseCIDR(e.CIDR); err == nil {
			nets = append(nets, n)
		}
	}
	return nets, nil
}
