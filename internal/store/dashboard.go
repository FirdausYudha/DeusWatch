package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"deuswatch/internal/ingest"
)

// Count is a generic label/count pair for a dashboard series.
type Count struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

// TimePoint is one bucket of the event timeline.
type TimePoint struct {
	Time  time.Time `json:"time"`
	Count int64     `json:"count"`
}

// DashboardData is the bundle of series the customizable dashboard renders from.
// Widgets pick a series by key; the timeline drives line/area charts and the
// "countries" series drives the attack-origins map.
type DashboardData struct {
	TotalEvents int64              `json:"total_events"`
	TotalAlerts int64              `json:"total_alerts"`
	Alerts24h   int64              `json:"alerts_24h"`
	Series      map[string][]Count `json:"series"`
	Timeline    []TimePoint        `json:"timeline"`
	// RiskyIPs is the composite-score leaderboard (score + band, not just a count), for the
	// "Top risky IPs" widget. Empty until the worker's IP scorer has run at least once.
	RiskyIPs []IPScore `json:"risky_ips"`
	// SuspiciousIPs is the low-and-slow reconnaissance watchlist, for the "Suspicious IPs" widget.
	SuspiciousIPs []SuspiciousIP `json:"suspicious_ips"`
}

// Dashboard assembles all dashboard series for the window [since, until].
func (s *Store) Dashboard(ctx context.Context, since, until time.Time) (DashboardData, error) {
	if until.IsZero() {
		until = time.Now()
	}
	if since.IsZero() || !since.Before(until) {
		since = until.Add(-24 * time.Hour)
	}
	d := DashboardData{Series: map[string][]Count{}}

	for _, q := range []struct {
		sql  string
		dest *int64
	}{
		{`SELECT count(*) FROM events`, &d.TotalEvents},
		{`SELECT count(*) FROM events WHERE dw_label IS NOT NULL`, &d.TotalAlerts},
		{`SELECT count(*) FROM events WHERE dw_label IS NOT NULL AND time > now() - interval '24 hours'`, &d.Alerts24h},
	} {
		if err := s.pool.QueryRow(ctx, q.sql).Scan(q.dest); err != nil {
			return d, fmt.Errorf("store: dashboard counters: %w", err)
		}
	}

	sev, err := s.dashSeverity(ctx, since, until)
	if err != nil {
		return d, err
	}
	d.Series["severity"] = sev

	for key, q := range map[string]string{
		"source_ips": `SELECT host(source_ip), count(*) FROM events
			WHERE time >= $1 AND time <= $2 AND source_ip IS NOT NULL AND dw_label IS NOT NULL
			GROUP BY source_ip ORDER BY count(*) DESC LIMIT 10`,
		"rules": `SELECT COALESCE(rule_name, rule_id), count(*) FROM events
			WHERE time >= $1 AND time <= $2 AND dw_label IS NOT NULL AND rule_id IS NOT NULL
			GROUP BY COALESCE(rule_name, rule_id) ORDER BY count(*) DESC LIMIT 10`,
		"techniques": `SELECT trim(COALESCE(threat_technique_id,'')||' '||COALESCE(threat_tactic_name,'')), count(*) FROM events
			WHERE time >= $1 AND time <= $2 AND threat_technique_id IS NOT NULL
			GROUP BY threat_technique_id, threat_tactic_name ORDER BY count(*) DESC LIMIT 10`,
		"countries": `SELECT source_geo_country_iso, count(*) FROM events
			WHERE time >= $1 AND time <= $2 AND source_geo_country_iso IS NOT NULL
			GROUP BY source_geo_country_iso ORDER BY count(*) DESC LIMIT 20`,
		"verdicts": `SELECT dw_llm_verdict, count(*) FROM events
			WHERE time >= $1 AND time <= $2 AND dw_llm_verdict IS NOT NULL
			GROUP BY dw_llm_verdict ORDER BY count(*) DESC`,
	} {
		c, err := s.dashCounts(ctx, q, since, until)
		if err != nil {
			return d, err
		}
		d.Series[key] = c
	}

	if d.Timeline, err = s.dashTimeline(ctx, since, until); err != nil {
		return d, err
	}
	// Composite-score leaderboard (already maintained by the worker's IP scorer). A failure
	// here shouldn't blank the whole dashboard, so log-and-continue with an empty list.
	if risky, rerr := s.TopIPScores(ctx, 10); rerr == nil {
		d.RiskyIPs = risky
	}
	if susp, serr := s.TopSuspiciousIPs(ctx, 10); serr == nil {
		d.SuspiciousIPs = susp
	}
	return d, nil
}

func (s *Store) dashSeverity(ctx context.Context, since, until time.Time) ([]Count, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT event_severity, count(*) FROM events
		 WHERE time >= $1 AND time <= $2 AND event_severity IS NOT NULL
		 GROUP BY event_severity ORDER BY event_severity DESC`, since, until)
	if err != nil {
		return nil, fmt.Errorf("store: dashboard severity: %w", err)
	}
	defer rows.Close()
	out := make([]Count, 0, 5)
	for rows.Next() {
		var sev int
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out = append(out, Count{Label: ingest.Severity(sev).String(), Count: n})
	}
	return out, rows.Err()
}

func (s *Store) dashCounts(ctx context.Context, query string, since, until time.Time) ([]Count, error) {
	rows, err := s.pool.Query(ctx, query, since, until)
	if err != nil {
		return nil, fmt.Errorf("store: dashboard series: %w", err)
	}
	defer rows.Close()
	out := make([]Count, 0, 10)
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Label, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// bucketFor picks a timeline bucket width so the chart always has a sensible
// number of points (~24-150) regardless of the selected window.
func bucketFor(span time.Duration) string {
	switch {
	case span <= 2*time.Hour:
		return "1 minute"
	case span <= 12*time.Hour:
		return "10 minutes"
	case span <= 3*24*time.Hour:
		return "1 hour"
	case span <= 21*24*time.Hour:
		return "6 hours"
	default:
		return "1 day"
	}
}

// dashTimeline returns a gap-filled series: every bucket across [since, until]
// is present (zero where there were no events) so the line renders continuously
// even when activity is sparse or confined to a single bucket.
func (s *Store) dashTimeline(ctx context.Context, since, until time.Time) ([]TimePoint, error) {
	bucket := bucketFor(until.Sub(since))
	rows, err := s.pool.Query(ctx,
		`SELECT g AS bucket, COALESCE(e.cnt, 0)
		 FROM generate_series(time_bucket($3::interval, $1), time_bucket($3::interval, $2), $3::interval) AS g
		 LEFT JOIN (
		     SELECT time_bucket($3::interval, time) AS b, count(*) AS cnt
		     FROM events WHERE time >= $1 AND time <= $2 GROUP BY b
		 ) e ON e.b = g
		 ORDER BY g`, since, until, bucket)
	if err != nil {
		return nil, fmt.Errorf("store: dashboard timeline: %w", err)
	}
	defer rows.Close()
	out := make([]TimePoint, 0, 48)
	for rows.Next() {
		var p TimePoint
		if err := rows.Scan(&p.Time, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetDashboardLayout returns the stored layout JSON for a user (nil if none).
func (s *Store) GetDashboardLayout(ctx context.Context, userID string) ([]byte, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT layout FROM user_dashboards WHERE user_id=$1`, userID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get dashboard layout: %w", err)
	}
	return raw, nil
}

// SaveDashboardLayout upserts a user's dashboard layout JSON.
func (s *Store) SaveDashboardLayout(ctx context.Context, userID string, layout []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_dashboards (user_id, layout) VALUES ($1,$2)
		 ON CONFLICT (user_id) DO UPDATE SET layout=$2, updated_at=now()`, userID, layout)
	if err != nil {
		return fmt.Errorf("store: save dashboard layout: %w", err)
	}
	return nil
}
