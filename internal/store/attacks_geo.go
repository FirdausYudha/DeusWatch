package store

import (
	"context"
	"fmt"
	"time"
)

// AttackOrigin is one source of attack traffic aggregated over a time window — a marker on the
// dashboard's animated geo map. Country + city come from the enrichment columns already populated
// on events (AbuseIPDB / OTX / MaxMind); lat/lon are looked up client-side from the bundled ISO →
// centroid table (docs/geo-map.md, decision A1). `Blocked` reflects whether this source IP has an
// active ban action right now, so an operator can tell "we saw them but they're already stopped"
// from "we saw them and they still can knock on our door".
type AttackOrigin struct {
	IP      string `json:"ip"`
	Country string `json:"country"` // ISO-3166 alpha-2, empty when the enricher didn't classify
	City    string `json:"city"`
	Count   int    `json:"count"`   // total alerts from this IP in the window
	Blocked bool   `json:"blocked"` // set by the API from response_actions
}

// AttackOrigins returns aggregated attack sources in the [since, until) window. Only labelled
// events count (dw_label IS NOT NULL) — an unlabelled event is just noise, we care about the
// alerts. External sources only: RFC1918 + loopback filtered out, so the widget doesn't get
// bombarded by our own internal traffic. Capped at `limit` (default 200) so the map stays
// bounded even during a brute-force burst.
func (s *Store) AttackOrigins(ctx context.Context, since, until time.Time, limit int) ([]AttackOrigin, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.q(ctx).Query(ctx, `
		SELECT host(source_ip)                       AS ip,
		       COALESCE(source_geo_country_iso,'')   AS country,
		       COALESCE(source_geo_city,'')          AS city,
		       count(*)                              AS n
		FROM events
		WHERE source_ip IS NOT NULL
		  AND dw_label IS NOT NULL
		  AND time >= $1 AND time < $2
		  AND NOT (source_ip <<= '10.0.0.0/8'::inet OR source_ip <<= '172.16.0.0/12'::inet
		        OR source_ip <<= '192.168.0.0/16'::inet OR source_ip <<= '127.0.0.0/8'::inet)
		GROUP BY source_ip, source_geo_country_iso, source_geo_city
		ORDER BY n DESC
		LIMIT $3`, since, until, limit)
	if err != nil {
		return nil, fmt.Errorf("store: attack origins: %w", err)
	}
	defer rows.Close()
	out := make([]AttackOrigin, 0, limit)
	for rows.Next() {
		var a AttackOrigin
		if err := rows.Scan(&a.IP, &a.Country, &a.City, &a.Count); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AttachBlockedFlag flips Blocked=true on every origin whose IP appears in `blocked`. Kept
// separate from AttackOrigins so the handler can decide when to skip the join (fast path when the
// response engine isn't wired) and so the store test can exercise the two pieces independently.
func AttachBlockedFlag(origins []AttackOrigin, blocked []string) {
	if len(blocked) == 0 || len(origins) == 0 {
		return
	}
	set := make(map[string]struct{}, len(blocked))
	for _, ip := range blocked {
		set[ip] = struct{}{}
	}
	for i := range origins {
		if _, ok := set[origins[i].IP]; ok {
			origins[i].Blocked = true
		}
	}
}
