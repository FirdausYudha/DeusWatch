package store

import (
	"context"
	"fmt"
	"time"

	"deuswatch/internal/ingest"
	"deuswatch/internal/report"
)

// BuildReport assembles the summary for the last `hours` hours.
func (s *Store) BuildReport(ctx context.Context, hours int) (report.Report, error) {
	if hours <= 0 || hours > 24*30 {
		hours = 24
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	r := report.Report{Generated: time.Now(), Since: since, WindowHours: hours}

	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM events WHERE time >= $1`, since).Scan(&r.TotalEvents); err != nil {
		return r, fmt.Errorf("store: report total: %w", err)
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM events WHERE time >= $1 AND dw_label IS NOT NULL`, since).Scan(&r.TotalAlerts); err != nil {
		return r, fmt.Errorf("store: report alerts: %w", err)
	}

	var err error
	if r.BySeverity, err = s.severityCounts(ctx, since); err != nil {
		return r, err
	}
	if r.TopSourceIPs, err = s.topCounts(ctx,
		`SELECT host(source_ip), count(*) FROM events
		 WHERE time >= $1 AND source_ip IS NOT NULL AND dw_label IS NOT NULL
		 GROUP BY source_ip ORDER BY count(*) DESC LIMIT 10`, since); err != nil {
		return r, err
	}
	if r.TopRules, err = s.topCounts(ctx,
		`SELECT COALESCE(rule_name, rule_id), count(*) FROM events
		 WHERE time >= $1 AND dw_label IS NOT NULL AND rule_id IS NOT NULL
		 GROUP BY COALESCE(rule_name, rule_id) ORDER BY count(*) DESC LIMIT 10`, since); err != nil {
		return r, err
	}
	if r.TopTechniques, err = s.topCounts(ctx,
		`SELECT COALESCE(threat_technique_id,'')||' '||COALESCE(threat_tactic_name,''), count(*) FROM events
		 WHERE time >= $1 AND threat_technique_id IS NOT NULL
		 GROUP BY threat_technique_id, threat_tactic_name ORDER BY count(*) DESC LIMIT 10`, since); err != nil {
		return r, err
	}
	if r.ByVerdict, err = s.topCounts(ctx,
		`SELECT dw_llm_verdict, count(*) FROM events
		 WHERE time >= $1 AND dw_llm_verdict IS NOT NULL
		 GROUP BY dw_llm_verdict ORDER BY count(*) DESC`, since); err != nil {
		return r, err
	}
	return r, nil
}

func (s *Store) severityCounts(ctx context.Context, since time.Time) ([]report.Count, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT event_severity, count(*) FROM events
		 WHERE time >= $1 AND dw_label IS NOT NULL AND event_severity IS NOT NULL
		 GROUP BY event_severity ORDER BY event_severity DESC`, since)
	if err != nil {
		return nil, fmt.Errorf("store: report severity: %w", err)
	}
	defer rows.Close()
	var out []report.Count
	for rows.Next() {
		var sev int
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out = append(out, report.Count{Label: ingest.Severity(sev).String(), Count: n})
	}
	return out, rows.Err()
}

func (s *Store) topCounts(ctx context.Context, query string, since time.Time) ([]report.Count, error) {
	rows, err := s.pool.Query(ctx, query, since)
	if err != nil {
		return nil, fmt.Errorf("store: report agg: %w", err)
	}
	defer rows.Close()
	var out []report.Count
	for rows.Next() {
		var c report.Count
		if err := rows.Scan(&c.Label, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
