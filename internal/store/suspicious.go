package store

import (
	"context"
	"fmt"
	"time"

	"deuswatch/internal/score"
)

// SuspiciousIP is one watchlist row: an external source IP whose behaviour over a long window
// looks like reconnaissance (low-and-slow scanning) even without any CTI/WAF hit.
type SuspiciousIP struct {
	IP            string    `json:"ip"`
	Contacts      int       `json:"contacts"`
	FanOut        int       `json:"fanout"`
	DistinctHours int       `json:"distinct_hours"`
	Failures      int       `json:"failures"`
	Score         int       `json:"score"`
	Band          string    `json:"band"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// suspiciousAggSQL computes the behavioral signals per EXTERNAL source IP over the window.
//
//   - fanout = the larger of "distinct URIs probed" and "distinct destination ports" — the
//     scanner tell (one client hitting many different things).
//   - failures = blocked / denied / 4xx / auth-failure events.
//   - distinct_hours = how many separate clock-hours the IP appeared in (spread over time is
//     the low-and-slow signature).
//
// RFC1918 / loopback are excluded: internal monitoring and health-checks are the main source of
// "touches us a lot" false positives, and the feature targets EXTERNAL recon. A minimum contact
// count keeps one-off noise out of the table.
const suspiciousAggSQL = `
SELECT host(source_ip)                                                       AS ip,
       count(*)                                                              AS contacts,
       GREATEST(
         count(DISTINCT http_uri)        FILTER (WHERE COALESCE(http_uri,'') <> ''),
         count(DISTINCT destination_port) FILTER (WHERE destination_port IS NOT NULL)
       )                                                                     AS fanout,
       count(DISTINCT date_trunc('hour', time))                             AS distinct_hours,
       count(*) FILTER (
         WHERE event_outcome IN ('failure','blocked','denied')
            OR event_action  IN ('waf_block','firewall_block')
            OR http_status >= 400
       )                                                                     AS failures,
       min(time) AS first_seen, max(time) AS last_seen
FROM events
WHERE source_ip IS NOT NULL
  AND time > now() - $1::interval
  AND NOT (source_ip <<= '10.0.0.0/8'::inet OR source_ip <<= '172.16.0.0/12'::inet
        OR source_ip <<= '192.168.0.0/16'::inet OR source_ip <<= '127.0.0.0/8'::inet)
GROUP BY source_ip
HAVING count(*) >= 3`

// RefreshSuspiciousIPs recomputes the watchlist over `window` and replaces the table. Rows are
// pruned by the full replace, so an IP that goes quiet drops off. Returns the rows (highest
// score first is not guaranteed here; the caller/query orders).
func (s *Store) RefreshSuspiciousIPs(ctx context.Context, window time.Duration) ([]SuspiciousIP, error) {
	rows, err := s.pool.Query(ctx, suspiciousAggSQL, fmt.Sprintf("%d seconds", int(window.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("store: suspicious query: %w", err)
	}
	defer rows.Close()

	w := score.DefaultSuspicionWeights()
	var out []SuspiciousIP
	for rows.Next() {
		var r SuspiciousIP
		if err := rows.Scan(&r.IP, &r.Contacts, &r.FanOut, &r.DistinctHours, &r.Failures,
			&r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		res := score.ComputeSuspicion(score.SuspicionSignals{
			Contacts: r.Contacts, FanOut: r.FanOut, Failures: r.Failures, DistinctHours: r.DistinctHours,
		}, w)
		r.Score, r.Band = res.Score, res.Band
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Full replace inside a transaction: the watchlist always reflects the current window.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM suspicious_ips`); err != nil {
		return out, fmt.Errorf("store: suspicious clear: %w", err)
	}
	for _, r := range out {
		if _, err := tx.Exec(ctx, `
			INSERT INTO suspicious_ips
			  (ip, contacts, fanout, distinct_hours, failures, score, band, first_seen, last_seen, updated_at)
			VALUES ($1::inet,$2,$3,$4,$5,$6,$7,$8,$9, now())`,
			r.IP, r.Contacts, r.FanOut, r.DistinctHours, r.Failures, r.Score, r.Band, r.FirstSeen, r.LastSeen); err != nil {
			return out, fmt.Errorf("store: suspicious insert: %w", err)
		}
	}
	return out, tx.Commit(ctx)
}

// TopSuspiciousIPs returns the highest-scoring watchlist entries (dashboard + report).
func (s *Store) TopSuspiciousIPs(ctx context.Context, limit int) ([]SuspiciousIP, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx,
		`SELECT host(ip), contacts, fanout, distinct_hours, failures, score, band, first_seen, last_seen
		 FROM suspicious_ips ORDER BY score DESC, contacts DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: top suspicious: %w", err)
	}
	defer rows.Close()
	var out []SuspiciousIP
	for rows.Next() {
		var r SuspiciousIP
		if err := rows.Scan(&r.IP, &r.Contacts, &r.FanOut, &r.DistinctHours, &r.Failures,
			&r.Score, &r.Band, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
