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
	// SlowScanners is the MULTI-DAY watchlist: sources that keep coming back at a volume too low
	// for any burst rule to fire. Independent of the dashboard time range (it is a days-long view).
	SlowScanners []SlowScanner `json:"slow_scanners"`
}

// Dashboard assembles all dashboard series for the window [since, until]. `bucketOverride`
// forces the timeline bucket width (e.g. "1 minute", "5 minutes", "1 hour"); "" = auto based
// on the window span.
func (s *Store) Dashboard(ctx context.Context, since, until time.Time, bucketOverride string) (DashboardData, error) {
	if until.IsZero() {
		until = time.Now()
	}
	if since.IsZero() || !since.Before(until) {
		since = until.Add(-24 * time.Hour)
	}
	d := DashboardData{Series: map[string][]Count{}}

	// Counters — all three windowed to [since, until] so a range change (1h → 6h → 24h) doesn't
	// silently scan the whole events hypertable every time. The Timescale chunk-time index prunes
	// off-window chunks, so a 1h refresh reads a couple of chunks instead of millions of rows.
	// TotalEvents/TotalAlerts used to be all-time counters — v2.11.1 rescopes them to the range
	// picker's window because that's what an operator toggling ranges actually cares about
	// (and the old unbounded queries dominated the dashboard's tail latency).
	for _, q := range []struct {
		sql  string
		dest *int64
	}{
		{`SELECT count(*) FROM events WHERE time >= $1 AND time <= $2`, &d.TotalEvents},
		{`SELECT count(*) FROM events WHERE time >= $1 AND time <= $2 AND dw_label IS NOT NULL`, &d.TotalAlerts},
		{`SELECT count(*) FROM events WHERE dw_label IS NOT NULL AND time > now() - interval '24 hours'`, &d.Alerts24h},
	} {
		var err error
		if q.dest == &d.Alerts24h {
			err = s.q(ctx).QueryRow(ctx, q.sql).Scan(q.dest)
		} else {
			err = s.q(ctx).QueryRow(ctx, q.sql, since, until).Scan(q.dest)
		}
		if err != nil {
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
		"destination_ports": `SELECT destination_port::text, count(*) FROM events
			WHERE time >= $1 AND time <= $2 AND destination_port IS NOT NULL
			GROUP BY destination_port ORDER BY count(*) DESC LIMIT 10`,
		"destination_ips": `SELECT COALESCE(host(destination_ip), agent_id, '(unknown)'), count(*) FROM events
			WHERE time >= $1 AND time <= $2 AND (destination_ip IS NOT NULL OR agent_id IS NOT NULL)
			GROUP BY 1 ORDER BY count(*) DESC LIMIT 10`,
	} {
		c, err := s.dashCounts(ctx, q, since, until)
		if err != nil {
			return d, err
		}
		d.Series[key] = c
	}

	if d.Timeline, err = s.dashTimeline(ctx, since, until, bucketOverride); err != nil {
		return d, err
	}
	// Traffic direction pie (v2.10.0): classifies every event in the window into
	// Inbound / Outbound / Lateral / Unknown using RFC1918 + loopback as the "internal" set.
	// Independent of the response engine's internal-nets whitelist to keep dashboard.go
	// self-contained; a per-tenant custom whitelist is a v2.11 concern.
	if dir, derr := s.dashDirectionCounts(ctx, since, until); derr == nil {
		d.Series["direction"] = dir
	}
	// Composite-score leaderboard (already maintained by the worker's IP scorer). A failure
	// here shouldn't blank the whole dashboard, so log-and-continue with an empty list.
	if risky, rerr := s.TopIPScores(ctx, 10); rerr == nil {
		d.RiskyIPs = risky
	}
	if susp, serr := s.TopSuspiciousIPs(ctx, 10); serr == nil {
		d.SuspiciousIPs = susp
	}
	if slow, serr := s.TopSlowScanners(ctx, 10); serr == nil {
		d.SlowScanners = slow
	}
	return d, nil
}

func (s *Store) dashSeverity(ctx context.Context, since, until time.Time) ([]Count, error) {
	rows, err := s.q(ctx).Query(ctx,
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
	rows, err := s.q(ctx).Query(ctx, query, since, until)
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

// TenantTimeline is one row of the multi-tenant event trend (superadmin view). Each series is a
// gap-filled per-bucket count for one tenant, so all series share the same X axis and can be
// stacked or overlaid on a single chart without alignment work in the frontend.
type TenantTimeline struct {
	TenantID   string      `json:"tenant_id"`
	TenantName string      `json:"tenant_name"`
	Points     []TimePoint `json:"points"`
}

// TenantTimelines returns per-tenant timelines for the window. Requires the calling scope to be
// superadmin (RLS bypass) — otherwise the events view only exposes the caller's own tenant and
// the result trivially collapses to one series (i.e. the same shape as the plain timeline).
// bucketOverride uses the same whitelist as dashTimeline.
func (s *Store) TenantTimelines(ctx context.Context, since, until time.Time, bucketOverride string) ([]TenantTimeline, error) {
	if until.IsZero() {
		until = time.Now()
	}
	if since.IsZero() || !since.Before(until) {
		since = until.Add(-24 * time.Hour)
	}
	bucket := bucketFor(until.Sub(since))
	if b, ok := allowedBuckets[bucketOverride]; ok {
		bucket = b
	}
	// One gap-filled series per tenant, resolved via LEFT JOIN so tenants with zero events in
	// the window still surface (as a flat line at 0) rather than disappearing. The tenant list
	// is intersected against tenants that have events in the WHOLE table (not just the window)
	// so a brand-new empty tenant doesn't clutter the chart.
	const q = `
WITH active_tenants AS (
    SELECT DISTINCT t.id, t.name
    FROM tenants t
    WHERE EXISTS(SELECT 1 FROM events e WHERE e.tenant_id = t.id)
),
buckets AS (
    SELECT g AS b FROM generate_series(
        time_bucket($3::interval, $1),
        time_bucket($3::interval, $2),
        $3::interval
    ) g
),
counts AS (
    SELECT
        e.tenant_id,
        time_bucket($3::interval, e.time) AS b,
        count(*) AS cnt
    FROM events e
    WHERE e.time >= $1 AND e.time <= $2
    GROUP BY 1, 2
)
SELECT
    at.id::text,
    at.name,
    bk.b,
    COALESCE(c.cnt, 0)
FROM active_tenants at
CROSS JOIN buckets bk
LEFT JOIN counts c ON c.tenant_id = at.id AND c.b = bk.b
ORDER BY at.name, bk.b`
	rows, err := s.q(ctx).Query(ctx, q, since, until, bucket)
	if err != nil {
		return nil, fmt.Errorf("store: tenant timelines: %w", err)
	}
	defer rows.Close()

	byID := make(map[string]*TenantTimeline)
	var order []string
	for rows.Next() {
		var (
			id, name string
			t        time.Time
			c        int64
		)
		if err := rows.Scan(&id, &name, &t, &c); err != nil {
			return nil, err
		}
		tt, ok := byID[id]
		if !ok {
			tt = &TenantTimeline{TenantID: id, TenantName: name}
			byID[id] = tt
			order = append(order, id)
		}
		tt.Points = append(tt.Points, TimePoint{Time: t, Count: c})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]TenantTimeline, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}

// dashDirectionCounts classifies every event in the window into Inbound / Outbound / Lateral /
// Unknown and returns tallies for the traffic-direction pie widget. Matches AttachDirection's
// logic (internal/store/direction.go) but runs in SQL so the pie summarizes the full window, not
// just the sample the events view returned. Internal-nets bootstrap uses RFC1918 + loopback only
// — a per-tenant custom whitelist is left for a future release.
func (s *Store) dashDirectionCounts(ctx context.Context, since, until time.Time) ([]Count, error) {
	// Pure boolean expression — no CTE, no correlated EXISTS. Faster because Postgres can push
	// the internal-net checks into the same seq/index scan as the time-window filter, instead of
	// materialising a "classified" intermediate row set with 2 subquery lookups per event. On a
	// 24h window with 100k+ events this alone shaved multiple seconds off the dashboard fetch.
	const q = `
SELECT
  CASE
    WHEN source_ip IS NULL THEN 'unknown'
    WHEN (source_ip <<= '10.0.0.0/8'::cidr OR source_ip <<= '172.16.0.0/12'::cidr OR source_ip <<= '192.168.0.0/16'::cidr OR source_ip <<= '127.0.0.0/8'::cidr)
      AND destination_ip IS NOT NULL
      AND (destination_ip <<= '10.0.0.0/8'::cidr OR destination_ip <<= '172.16.0.0/12'::cidr OR destination_ip <<= '192.168.0.0/16'::cidr OR destination_ip <<= '127.0.0.0/8'::cidr)
      THEN 'lateral'
    WHEN (source_ip <<= '10.0.0.0/8'::cidr OR source_ip <<= '172.16.0.0/12'::cidr OR source_ip <<= '192.168.0.0/16'::cidr OR source_ip <<= '127.0.0.0/8'::cidr)
      AND destination_ip IS NOT NULL
      THEN 'outbound'
    WHEN NOT (source_ip <<= '10.0.0.0/8'::cidr OR source_ip <<= '172.16.0.0/12'::cidr OR source_ip <<= '192.168.0.0/16'::cidr OR source_ip <<= '127.0.0.0/8'::cidr)
      AND (destination_ip IS NOT NULL OR (agent_id IS NOT NULL AND agent_id <> ''))
      THEN 'inbound'
    WHEN (source_ip <<= '10.0.0.0/8'::cidr OR source_ip <<= '172.16.0.0/12'::cidr OR source_ip <<= '192.168.0.0/16'::cidr OR source_ip <<= '127.0.0.0/8'::cidr)
      AND destination_ip IS NULL
      AND (agent_id IS NOT NULL AND agent_id <> '')
      THEN 'lateral'
    ELSE 'unknown'
  END AS direction,
  count(*)
FROM events
WHERE time >= $1 AND time <= $2
GROUP BY 1
ORDER BY 2 DESC`
	rows, err := s.q(ctx).Query(ctx, q, since, until)
	if err != nil {
		return nil, fmt.Errorf("store: dashboard direction: %w", err)
	}
	defer rows.Close()
	out := make([]Count, 0, 4)
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Label, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// allowedBuckets whitelists the operator-selectable bucket widths for the timeline widget.
// The map key is what the API accepts on ?bucket=; the value is the TimescaleDB interval
// literal fed to time_bucket(). Anything else falls through to bucketFor's automatic pick
// (never trust a caller-supplied interval string in raw SQL).
var allowedBuckets = map[string]string{
	"1min":  "1 minute",
	"5min":  "5 minutes",
	"15min": "15 minutes",
	"30min": "30 minutes",
	"1h":    "1 hour",
	"6h":    "6 hours",
	"1d":    "1 day",
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
// even when activity is sparse or confined to a single bucket. `bucketOverride`
// forces a specific TimescaleDB interval literal ("1 minute", "5 minutes", …);
// unrecognized values (or "") fall back to bucketFor(span).
func (s *Store) dashTimeline(ctx context.Context, since, until time.Time, bucketOverride string) ([]TimePoint, error) {
	bucket := bucketFor(until.Sub(since))
	if b, ok := allowedBuckets[bucketOverride]; ok {
		bucket = b
	}
	rows, err := s.q(ctx).Query(ctx,
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
	err := s.q(ctx).QueryRow(ctx, `SELECT layout FROM user_dashboards WHERE user_id=$1`, userID).Scan(&raw)
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
	_, err := s.q(ctx).Exec(ctx,
		`INSERT INTO user_dashboards (user_id, layout) VALUES ($1,$2)
		 ON CONFLICT (user_id) DO UPDATE SET layout=$2, updated_at=now()`, userID, layout)
	if err != nil {
		return fmt.Errorf("store: save dashboard layout: %w", err)
	}
	return nil
}

// DeleteDashboardLayout removes a user's saved layout, so the dashboard falls back to the default
// PANELS order. Idempotent — no error when the row doesn't exist.
func (s *Store) DeleteDashboardLayout(ctx context.Context, userID string) error {
	_, err := s.q(ctx).Exec(ctx, `DELETE FROM user_dashboards WHERE user_id=$1`, userID)
	if err != nil {
		return fmt.Errorf("store: delete dashboard layout: %w", err)
	}
	return nil
}
