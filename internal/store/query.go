package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// EventRow is a flat representation of one event for the API/UI.
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
	// CTI / GeoIP enrichment (for the alert view).
	GeoCountry      string `json:"source_geo_country_iso"`
	GeoCity         string `json:"source_geo_city"`
	FeedName        string `json:"threat_feed_name"`
	AbuseConfidence *int   `json:"dw_enrichment_abuse_confidence"`
	OTXPulseCount   *int   `json:"dw_enrichment_otx_pulse_count"`
	EnrichStatus    string `json:"dw_enrichment_status"`
	EscalatedBy     string `json:"dw_severity_escalated_by"`
	LLMVerdict      string `json:"dw_llm_verdict"`
	LLMSummary      string `json:"dw_llm_summary"`
	// FIM file-hash reputation.
	FilePath        string `json:"file_path"`
	FileHash        string `json:"file_hash_sha256"`
	FileHashVerdict string `json:"dw_filehash_verdict"`
	FileHashDetail  string `json:"dw_filehash_detail"`
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
	COALESCE(dw_llm_verdict,''), COALESCE(dw_llm_summary,''),
	COALESCE(file_path,''), COALESCE(file_hash_sha256,''),
	COALESCE(dw_filehash_verdict,''), COALESCE(dw_filehash_detail,'')`

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
			&e.FilePath, &e.FileHash, &e.FileHashVerdict, &e.FileHashDetail,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecentEvents returns the most recent events (live log stream).
func (s *Store) RecentEvents(ctx context.Context, limit int) ([]EventRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+selectCols+` FROM events ORDER BY time DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: recent events: %w", err)
	}
	return scanEventRows(rows)
}

// RecentAlerts returns the most recent labeled events (alerts).
func (s *Store) RecentAlerts(ctx context.Context, limit int) ([]EventRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+selectCols+` FROM events WHERE dw_label IS NOT NULL ORDER BY time DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: recent alerts: %w", err)
	}
	return scanEventRows(rows)
}

// FileTarget is a known-bad file (path + hash) agents may quarantine/delete.
type FileTarget struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// QuarantineTargets returns distinct known-bad files (FIM hash reputation = known_bad)
// seen recently. Agents self-filter by re-hashing the path locally, so this list is global.
func (s *Store) QuarantineTargets(ctx context.Context) ([]FileTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT file_path, file_hash_sha256 FROM events
		WHERE dw_filehash_verdict = 'known_bad'
		  AND file_path IS NOT NULL AND file_path <> ''
		  AND file_hash_sha256 IS NOT NULL AND file_hash_sha256 <> ''
		  AND time > now() - interval '30 days'`)
	if err != nil {
		return nil, fmt.Errorf("store: quarantine targets: %w", err)
	}
	defer rows.Close()
	out := make([]FileTarget, 0, 16)
	for rows.Next() {
		var ft FileTarget
		if err := rows.Scan(&ft.Path, &ft.SHA256); err != nil {
			return nil, err
		}
		out = append(out, ft)
	}
	return out, rows.Err()
}

// EventFilter holds the optional search criteria for SearchEvents. Zero-value fields
// are ignored, so any combination narrows the result.
type EventFilter struct {
	Text        string    // free text over original/rule/host/user/file/label
	SourceIP    string    // substring match on the source IP
	RuleID      string    // substring on rule_id OR rule_name
	TechniqueID string    // substring on the MITRE technique id
	Category    string    // exact event.category
	MinSeverity int       // event_severity >= this (-1 = any)
	AlertsOnly  bool      // only labeled events (alerts)
	From, To    time.Time // time window (zero = unbounded)
	Limit       int
}

// SearchEvents returns events matching the filter, most recent first. It is the backing
// query for the dashboard's searchable Events/Alerts table.
func (s *Store) SearchEvents(ctx context.Context, f EventFilter) ([]EventRow, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 50
	}
	var conds []string
	var args []any
	like := func(col, val string) {
		args = append(args, "%"+val+"%")
		conds = append(conds, fmt.Sprintf("%s ILIKE $%d", col, len(args)))
	}
	if f.AlertsOnly {
		conds = append(conds, "dw_label IS NOT NULL")
	}
	if f.Text != "" {
		args = append(args, "%"+f.Text+"%")
		n := len(args)
		// General search bar: also match the source IP + rule id/technique so users can
		// search by IP (alerts have no raw event_original text to fall back on) or rule.
		conds = append(conds, fmt.Sprintf(
			"(host(source_ip) ILIKE $%d OR event_original ILIKE $%d OR rule_name ILIKE $%d OR rule_id ILIKE $%d OR host_name ILIKE $%d OR user_name ILIKE $%d OR file_path ILIKE $%d OR dw_label ILIKE $%d OR threat_technique_id ILIKE $%d)",
			n, n, n, n, n, n, n, n, n))
	}
	if f.SourceIP != "" {
		args = append(args, "%"+f.SourceIP+"%")
		conds = append(conds, fmt.Sprintf("host(source_ip) ILIKE $%d", len(args)))
	}
	if f.RuleID != "" {
		args = append(args, "%"+f.RuleID+"%")
		n := len(args)
		conds = append(conds, fmt.Sprintf("(rule_id ILIKE $%d OR rule_name ILIKE $%d)", n, n))
	}
	if f.TechniqueID != "" {
		like("threat_technique_id", f.TechniqueID)
	}
	if f.Category != "" {
		args = append(args, f.Category)
		conds = append(conds, fmt.Sprintf("event_category = $%d", len(args)))
	}
	if f.MinSeverity >= 0 {
		args = append(args, f.MinSeverity)
		conds = append(conds, fmt.Sprintf("event_severity >= $%d", len(args)))
	}
	if !f.From.IsZero() {
		args = append(args, f.From)
		conds = append(conds, fmt.Sprintf("time >= $%d", len(args)))
	}
	if !f.To.IsZero() {
		args = append(args, f.To)
		conds = append(conds, fmt.Sprintf("time <= $%d", len(args)))
	}

	q := `SELECT ` + selectCols + ` FROM events`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, f.Limit)
	q += fmt.Sprintf(" ORDER BY time DESC LIMIT $%d", len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: search events: %w", err)
	}
	return scanEventRows(rows)
}

// IPCount / SeverityCount for dashboard widgets.
type IPCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}
type SeverityCount struct {
	Severity int   `json:"severity"`
	Count    int64 `json:"count"`
}

// Stats summarizes the events table for the dashboard.
type Stats struct {
	TotalEvents  int64           `json:"total_events"`
	TotalAlerts  int64           `json:"total_alerts"`
	Alerts24h    int64           `json:"alerts_24h"`
	TopSourceIPs []IPCount       `json:"top_source_ips"`
	BySeverity   []SeverityCount `json:"by_severity"`
}

// Stats gathers the summary for the dashboard.
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
