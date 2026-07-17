package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"deuswatch/internal/ingest"
	"deuswatch/internal/report"
)

// ReportSummary is one stored AI-generated executive summary.
type ReportSummary struct {
	Summary     string    `json:"summary"`
	Model       string    `json:"model"`
	PeriodHours int       `json:"period_hours"`
	GeneratedAt time.Time `json:"generated_at"`
}

// SaveReportSummary stores a generated summary.
func (s *Store) SaveReportSummary(ctx context.Context, periodHours int, summary, model string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO report_summaries (period_hours, summary, model) VALUES ($1,$2,$3)`,
		periodHours, summary, model)
	if err != nil {
		return fmt.Errorf("store: save report summary: %w", err)
	}
	return nil
}

// LatestReportSummary returns the most recent stored summary (ok=false if none).
func (s *Store) LatestReportSummary(ctx context.Context) (ReportSummary, bool, error) {
	var rs ReportSummary
	err := s.pool.QueryRow(ctx,
		`SELECT summary, model, period_hours, generated_at FROM report_summaries ORDER BY generated_at DESC LIMIT 1`).
		Scan(&rs.Summary, &rs.Model, &rs.PeriodHours, &rs.GeneratedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReportSummary{}, false, nil
	}
	if err != nil {
		return ReportSummary{}, false, fmt.Errorf("store: latest report summary: %w", err)
	}
	return rs, true, nil
}

// NotifyConfig holds the alert severity threshold + scheduled report-delivery settings.
type NotifyConfig struct {
	MinSeverity         int        `json:"min_severity"`
	ReportIntervalHours int        `json:"report_interval_hours"` // 0 = no scheduled delivery
	ReportPeriodHours   int        `json:"report_period_hours"`
	ReportLastSentAt    *time.Time `json:"report_last_sent_at,omitempty"`
}

// LoadNotifyConfig reads the notification config (defaults: severity medium, delivery off).
func (s *Store) LoadNotifyConfig(ctx context.Context) (NotifyConfig, error) {
	c := NotifyConfig{MinSeverity: 2, ReportPeriodHours: 24}
	err := s.pool.QueryRow(ctx,
		`SELECT min_severity, report_interval_hours, report_period_hours, report_last_sent_at
		 FROM notify_config WHERE id = 1`).
		Scan(&c.MinSeverity, &c.ReportIntervalHours, &c.ReportPeriodHours, &c.ReportLastSentAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("store: load notify config: %w", err)
	}
	return c, nil
}

// SaveNotifyConfig upserts the config (preserving report_last_sent_at).
func (s *Store) SaveNotifyConfig(ctx context.Context, c NotifyConfig) error {
	if c.ReportPeriodHours <= 0 {
		c.ReportPeriodHours = 24
	}
	if c.MinSeverity < 0 {
		c.MinSeverity = 0
	}
	if c.MinSeverity > 4 {
		c.MinSeverity = 4
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO notify_config (id, min_severity, report_interval_hours, report_period_hours) VALUES (1,$1,$2,$3)
		 ON CONFLICT (id) DO UPDATE SET min_severity=$1, report_interval_hours=$2, report_period_hours=$3, updated_at=now()`,
		c.MinSeverity, c.ReportIntervalHours, c.ReportPeriodHours)
	if err != nil {
		return fmt.Errorf("store: save notify config: %w", err)
	}
	return nil
}

// MarkReportDelivered records that a scheduled report was just sent.
func (s *Store) MarkReportDelivered(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO notify_config (id, report_last_sent_at) VALUES (1, now())
		 ON CONFLICT (id) DO UPDATE SET report_last_sent_at = now()`)
	if err != nil {
		return fmt.Errorf("store: mark report delivered: %w", err)
	}
	return nil
}

// ReportAIConfig is the schedule for auto-generating the AI report summary.
type ReportAIConfig struct {
	IntervalHours int    `json:"interval_hours"` // 0 = disabled
	PeriodHours   int    `json:"period_hours"`   // window each summary covers
	SummaryPrompt string `json:"summary_prompt"` // custom system prompt ("" = built-in default)
	// AtHour pins the run to an hour of the day (0..23, server local time). -1 = run on the
	// drifting interval instead (fire IntervalHours after the previous run, whenever that was).
	AtHour int `json:"at_hour"`
}

// LoadReportAIConfig reads the schedule (defaults: disabled, 24h window, drifting interval).
func (s *Store) LoadReportAIConfig(ctx context.Context) (ReportAIConfig, error) {
	c := ReportAIConfig{IntervalHours: 0, PeriodHours: 24, AtHour: -1}
	err := s.pool.QueryRow(ctx,
		`SELECT interval_hours, period_hours, COALESCE(summary_prompt,''), COALESCE(at_hour,-1)
		 FROM report_ai_config WHERE id = 1`).
		Scan(&c.IntervalHours, &c.PeriodHours, &c.SummaryPrompt, &c.AtHour)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("store: load report ai config: %w", err)
	}
	return c, nil
}

// SaveReportAIConfig upserts the schedule (single row).
func (s *Store) SaveReportAIConfig(ctx context.Context, c ReportAIConfig) error {
	if c.PeriodHours <= 0 {
		c.PeriodHours = 24
	}
	if c.IntervalHours < 0 {
		c.IntervalHours = 0
	}
	if len(c.SummaryPrompt) > 8000 {
		c.SummaryPrompt = c.SummaryPrompt[:8000]
	}
	if c.AtHour < 0 || c.AtHour > 23 {
		c.AtHour = -1 // anything outside 0..23 means "no fixed hour"
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO report_ai_config (id, interval_hours, period_hours, summary_prompt, at_hour) VALUES (1,$1,$2,$3,$4)
		 ON CONFLICT (id) DO UPDATE SET interval_hours=$1, period_hours=$2, summary_prompt=$3, at_hour=$4, updated_at=now()`,
		c.IntervalHours, c.PeriodHours, c.SummaryPrompt, c.AtHour)
	if err != nil {
		return fmt.Errorf("store: save report ai config: %w", err)
	}
	return nil
}

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
	if r.TopAgents, err = s.topCounts(ctx,
		`SELECT agent_id, count(*) FROM events
		 WHERE time >= $1 AND dw_label IS NOT NULL AND agent_id IS NOT NULL AND agent_id <> ''
		 GROUP BY agent_id ORDER BY count(*) DESC LIMIT 10`, since); err != nil {
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
