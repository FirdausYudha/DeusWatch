package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// EventRow adalah representasi datar satu event untuk API/UI.
type EventRow struct {
	Time        time.Time `json:"time"`
	Category    string    `json:"event_category"`
	Action      string    `json:"event_action"`
	Outcome     string    `json:"event_outcome"`
	Severity    int       `json:"event_severity"`
	Dataset     string    `json:"event_dataset"`
	SourceIP    string    `json:"source_ip"`
	HostName    string    `json:"host_name"`
	UserName    string    `json:"user_name"`
	RuleID      string    `json:"rule_id"`
	RuleName    string    `json:"rule_name"`
	TechniqueID string    `json:"threat_technique_id"`
	TacticName  string    `json:"threat_tactic_name"`
	Label       string    `json:"dw_label"`
	Original    string    `json:"event_original"`
	// Enrichment CTI / GeoIP (untuk tampilan alert).
	GeoCountry      string `json:"source_geo_country_iso"`
	GeoCity         string `json:"source_geo_city"`
	FeedName        string `json:"threat_feed_name"`
	AbuseConfidence *int   `json:"dw_enrichment_abuse_confidence"`
	OTXPulseCount   *int   `json:"dw_enrichment_otx_pulse_count"`
	EnrichStatus    string `json:"dw_enrichment_status"`
	EscalatedBy     string `json:"dw_severity_escalated_by"`
	LLMVerdict      string `json:"dw_llm_verdict"`
	LLMSummary      string `json:"dw_llm_summary"`
}

const selectCols = `
	time,
	COALESCE(event_category,''), COALESCE(event_action,''), COALESCE(event_outcome,''),
	COALESCE(event_severity,0), COALESCE(event_dataset,''),
	COALESCE(host(source_ip),''), COALESCE(host_name,''), COALESCE(user_name,''),
	COALESCE(rule_id,''), COALESCE(rule_name,''),
	COALESCE(threat_technique_id,''), COALESCE(threat_tactic_name,''),
	COALESCE(dw_label,''), COALESCE(event_original,''),
	COALESCE(source_geo_country_iso,''), COALESCE(source_geo_city,''), COALESCE(threat_feed_name,''),
	dw_enrichment_abuse_confidence, dw_enrichment_otx_pulse_count,
	COALESCE(dw_enrichment_status,''), COALESCE(dw_severity_escalated_by,''),
	COALESCE(dw_llm_verdict,''), COALESCE(dw_llm_summary,'')`

func scanEventRows(rows pgx.Rows) ([]EventRow, error) {
	defer rows.Close()
	out := make([]EventRow, 0, 64)
	for rows.Next() {
		var e EventRow
		if err := rows.Scan(
			&e.Time, &e.Category, &e.Action, &e.Outcome, &e.Severity, &e.Dataset,
			&e.SourceIP, &e.HostName, &e.UserName, &e.RuleID, &e.RuleName,
			&e.TechniqueID, &e.TacticName, &e.Label, &e.Original,
			&e.GeoCountry, &e.GeoCity, &e.FeedName,
			&e.AbuseConfidence, &e.OTXPulseCount, &e.EnrichStatus, &e.EscalatedBy,
			&e.LLMVerdict, &e.LLMSummary,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecentEvents mengembalikan event terbaru (live log stream).
func (s *Store) RecentEvents(ctx context.Context, limit int) ([]EventRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+selectCols+` FROM events ORDER BY time DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: recent events: %w", err)
	}
	return scanEventRows(rows)
}

// RecentAlerts mengembalikan event ber-label (alert) terbaru.
func (s *Store) RecentAlerts(ctx context.Context, limit int) ([]EventRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+selectCols+` FROM events WHERE dw_label IS NOT NULL ORDER BY time DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: recent alerts: %w", err)
	}
	return scanEventRows(rows)
}

// IPCount / SeverityCount untuk widget dashboard.
type IPCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}
type SeverityCount struct {
	Severity int   `json:"severity"`
	Count    int64 `json:"count"`
}

// Stats meringkas isi tabel events untuk dashboard.
type Stats struct {
	TotalEvents  int64           `json:"total_events"`
	TotalAlerts  int64           `json:"total_alerts"`
	Alerts24h    int64           `json:"alerts_24h"`
	TopSourceIPs []IPCount       `json:"top_source_ips"`
	BySeverity   []SeverityCount `json:"by_severity"`
}

// Stats mengumpulkan ringkasan untuk dashboard.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&st.TotalEvents); err != nil {
		return st, fmt.Errorf("store: stats total: %w", err)
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE dw_label IS NOT NULL`).Scan(&st.TotalAlerts); err != nil {
		return st, fmt.Errorf("store: stats alerts: %w", err)
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM events WHERE dw_label IS NOT NULL AND time > now() - interval '24 hours'`).
		Scan(&st.Alerts24h); err != nil {
		return st, fmt.Errorf("store: stats alerts24h: %w", err)
	}

	ipRows, err := s.pool.Query(ctx,
		`SELECT host(source_ip), count(*) FROM events WHERE source_ip IS NOT NULL
		 GROUP BY source_ip ORDER BY count(*) DESC LIMIT 5`)
	if err != nil {
		return st, fmt.Errorf("store: stats top ips: %w", err)
	}
	for ipRows.Next() {
		var c IPCount
		if err := ipRows.Scan(&c.IP, &c.Count); err != nil {
			ipRows.Close()
			return st, err
		}
		st.TopSourceIPs = append(st.TopSourceIPs, c)
	}
	ipRows.Close()
	if err := ipRows.Err(); err != nil {
		return st, err
	}

	sevRows, err := s.pool.Query(ctx,
		`SELECT event_severity, count(*) FROM events WHERE event_severity IS NOT NULL
		 GROUP BY event_severity ORDER BY event_severity`)
	if err != nil {
		return st, fmt.Errorf("store: stats severity: %w", err)
	}
	for sevRows.Next() {
		var c SeverityCount
		if err := sevRows.Scan(&c.Severity, &c.Count); err != nil {
			sevRows.Close()
			return st, err
		}
		st.BySeverity = append(st.BySeverity, c)
	}
	sevRows.Close()
	return st, sevRows.Err()
}
