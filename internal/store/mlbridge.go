package store

import (
	"context"
	"fmt"
	"time"
)

// IPFeature is the per-IP feature vector an external ML batch (e.g. an Isolation Forest) consumes
// to detect low-and-slow scanners. These are RAW behavioral features over the window — the same
// signals the built-in heuristic watchlist uses, exposed for a real model.
type IPFeature struct {
	IP            string    `json:"ip"`
	Contacts      int       `json:"contacts"`        // total events
	DistinctURIs  int       `json:"distinct_uris"`   // unique URIs probed
	DistinctPorts int       `json:"distinct_ports"`  // unique destination ports probed
	DistinctHours int       `json:"distinct_hours"`  // unique clock-hours seen (time spread)
	Failures      int       `json:"failures"`        // blocked / denied / 4xx / auth-fail
	SpanSecs      float64   `json:"span_secs"`       // last_seen - first_seen
	AvgGapSecs    float64   `json:"avg_gap_secs"`    // mean inter-event gap (interval regularity…)
	GapStddevSecs float64   `json:"gap_stddev_secs"` // …with its stddev — low CV = very regular
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// IPFeatures computes the feature vectors for external source IPs over the window. Same
// RFC1918/loopback exclusion as the watchlist; a minimum contact count keeps one-offs out.
func (s *Store) IPFeatures(ctx context.Context, window time.Duration, limit int) ([]IPFeature, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `
WITH ev AS (
  SELECT host(source_ip) AS ip, time, http_uri, destination_port, event_outcome, event_action, http_status
  FROM events
  WHERE source_ip IS NOT NULL AND time > now() - $1::interval
    AND NOT (source_ip <<= '10.0.0.0/8'::inet OR source_ip <<= '172.16.0.0/12'::inet
          OR source_ip <<= '192.168.0.0/16'::inet OR source_ip <<= '127.0.0.0/8'::inet)
),
agg AS (
  SELECT ip, count(*) AS contacts,
         count(DISTINCT http_uri) FILTER (WHERE COALESCE(http_uri,'') <> '') AS distinct_uris,
         count(DISTINCT destination_port) FILTER (WHERE destination_port IS NOT NULL) AS distinct_ports,
         count(DISTINCT date_trunc('hour', time)) AS distinct_hours,
         count(*) FILTER (WHERE event_outcome IN ('failure','blocked','denied')
                             OR event_action IN ('waf_block','firewall_block')
                             OR http_status >= 400) AS failures,
         min(time) AS first_seen, max(time) AS last_seen
  FROM ev GROUP BY ip
),
gaps AS (
  SELECT ip, EXTRACT(EPOCH FROM (time - lag(time) OVER (PARTITION BY ip ORDER BY time))) AS gap FROM ev
),
gapstats AS (
  SELECT ip, avg(gap) AS avg_gap, stddev_pop(gap) AS gap_sd FROM gaps WHERE gap IS NOT NULL GROUP BY ip
)
SELECT a.ip, a.contacts, a.distinct_uris, a.distinct_ports, a.distinct_hours, a.failures,
       EXTRACT(EPOCH FROM (a.last_seen - a.first_seen)) AS span_secs,
       COALESCE(gs.avg_gap,0), COALESCE(gs.gap_sd,0), a.first_seen, a.last_seen
FROM agg a LEFT JOIN gapstats gs ON gs.ip = a.ip
WHERE a.contacts >= 2
ORDER BY a.contacts DESC
LIMIT $2`, fmt.Sprintf("%d seconds", int(window.Seconds())), limit)
	if err != nil {
		return nil, fmt.Errorf("store: ip features: %w", err)
	}
	defer rows.Close()
	out := make([]IPFeature, 0, 64)
	for rows.Next() {
		var f IPFeature
		if err := rows.Scan(&f.IP, &f.Contacts, &f.DistinctURIs, &f.DistinctPorts, &f.DistinctHours,
			&f.Failures, &f.SpanSecs, &f.AvgGapSecs, &f.GapStddevSecs, &f.FirstSeen, &f.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// IPAnomaly is one anomaly_score writeback entry from the ML batch.
type IPAnomaly struct {
	IP      string `json:"ip"`
	Anomaly int    `json:"anomaly"` // 0..100
}

// SetIPAnomalies upserts anomaly scores written back by the ML batch. The composite scorer folds
// these in on its next run (subject to the UI-tunable anomaly weight).
func (s *Store) SetIPAnomalies(ctx context.Context, entries []IPAnomaly) (int, error) {
	n := 0
	for _, e := range entries {
		a := e.Anomaly
		if a < 0 {
			a = 0
		}
		if a > 100 {
			a = 100
		}
		if _, err := s.pool.Exec(ctx,
			`INSERT INTO ip_anomaly (ip, anomaly, updated_at) VALUES ($1::inet, $2, now())
			 ON CONFLICT (ip) DO UPDATE SET anomaly = $2, updated_at = now()`, e.IP, a); err != nil {
			return n, fmt.Errorf("store: set anomaly %s: %w", e.IP, err)
		}
		n++
	}
	// Age out stale anomaly scores (ML no longer reports them) after a day.
	_, _ = s.pool.Exec(ctx, `DELETE FROM ip_anomaly WHERE updated_at < now() - interval '24 hours'`)
	return n, nil
}
