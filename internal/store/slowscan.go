package store

import (
	"context"
	"fmt"
	"time"

	"deuswatch/internal/score"
)

// SlowScanner is one low-and-slow reconnaissance source: an IP that keeps coming back on separate
// days at a volume too low for any burst rule to fire.
type SlowScanner struct {
	IP         string     `json:"ip"`
	Score      int        `json:"score"`
	Band       string     `json:"band"`
	ActiveDays int        `json:"active_days"`
	SpanDays   int        `json:"span_days"`
	Events     int        `json:"events"`
	Targets    int        `json:"targets"`
	Agents     int        `json:"agents"`
	FirstSeen  *time.Time `json:"first_seen,omitempty"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// RefreshSlowScanners recomputes the slow-scanner watchlist over a multi-day window and replaces
// the table. Only EXTERNAL sources are considered (RFC1918/loopback excluded — internal hosts talk
// to each other all day, which is not reconnaissance), and only IPs that came back on enough
// separate days qualify, so the list stays short and meaningful.
func (s *Store) RefreshSlowScanners(ctx context.Context, window time.Duration, w score.SlowScanWeights) ([]SlowScanner, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT host(source_ip)                                          AS ip,
		       count(DISTINCT date_trunc('day', time))                  AS active_days,
		       GREATEST(0, EXTRACT(DAY FROM (max(time) - min(time))))::int AS span_days,
		       count(*)                                                 AS events,
		       GREATEST(
		         count(DISTINCT COALESCE(http_uri, '')) FILTER (WHERE http_uri IS NOT NULL AND http_uri <> ''),
		         count(DISTINCT destination_port) FILTER (WHERE destination_port IS NOT NULL)
		       )                                                        AS targets,
		       count(DISTINCT agent_id) FILTER (WHERE agent_id IS NOT NULL AND agent_id <> '') AS agents,
		       min(time)                                                AS first_seen,
		       max(time)                                                AS last_seen
		FROM events
		WHERE source_ip IS NOT NULL
		  AND time > now() - $1::interval
		  AND NOT (source_ip <<= '10.0.0.0/8'
		        OR source_ip <<= '172.16.0.0/12'
		        OR source_ip <<= '192.168.0.0/16'
		        OR source_ip <<= '127.0.0.0/8')
		GROUP BY source_ip`, fmt.Sprintf("%d seconds", int(window.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("store: slow-scan query: %w", err)
	}
	defer rows.Close()

	var out []SlowScanner
	for rows.Next() {
		var r SlowScanner
		if err := rows.Scan(&r.IP, &r.ActiveDays, &r.SpanDays, &r.Events, &r.Targets, &r.Agents,
			&r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		sig := score.SlowScanSignals{
			ActiveDays: r.ActiveDays, SpanDays: r.SpanDays, Events: r.Events, Targets: r.Targets,
		}
		if !w.Qualifies(sig) {
			continue // not recurrent enough to be a pattern
		}
		res := score.ComputeSlowScan(sig, w)
		r.Score, r.Band = res.Score, res.Band
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Replace the watchlist: a source that stopped coming back should drop off.
	if _, err := s.pool.Exec(ctx, `DELETE FROM slow_scanners`); err != nil {
		return nil, fmt.Errorf("store: slow-scan clear: %w", err)
	}
	for _, r := range out {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO slow_scanners (ip, score, band, active_days, span_days, events, targets, agents, first_seen, last_seen, updated_at)
			VALUES ($1::inet,$2,$3,$4,$5,$6,$7,$8,$9,$10, now())
			ON CONFLICT (ip) DO UPDATE SET
			  score=EXCLUDED.score, band=EXCLUDED.band, active_days=EXCLUDED.active_days,
			  span_days=EXCLUDED.span_days, events=EXCLUDED.events, targets=EXCLUDED.targets,
			  agents=EXCLUDED.agents, first_seen=EXCLUDED.first_seen, last_seen=EXCLUDED.last_seen,
			  updated_at=now()`,
			r.IP, r.Score, r.Band, r.ActiveDays, r.SpanDays, r.Events, r.Targets, r.Agents,
			r.FirstSeen, r.LastSeen); err != nil {
			return nil, fmt.Errorf("store: slow-scan upsert: %w", err)
		}
	}
	return out, nil
}

// TopSlowScanners returns the highest-scoring slow scanners for the dashboard widget.
func (s *Store) TopSlowScanners(ctx context.Context, limit int) ([]SlowScanner, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `
		SELECT host(ip), score, band, active_days, span_days, events, targets, agents,
		       first_seen, last_seen, updated_at
		FROM slow_scanners ORDER BY score DESC, active_days DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: top slow scanners: %w", err)
	}
	defer rows.Close()
	out := make([]SlowScanner, 0, limit)
	for rows.Next() {
		var r SlowScanner
		if err := rows.Scan(&r.IP, &r.Score, &r.Band, &r.ActiveDays, &r.SpanDays, &r.Events,
			&r.Targets, &r.Agents, &r.FirstSeen, &r.LastSeen, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
