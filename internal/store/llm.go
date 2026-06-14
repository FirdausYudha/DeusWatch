package store

import (
	"context"
	"fmt"
	"time"
)

// LLMAlert is an alert awaiting LLM analysis (with its id for the update).
type LLMAlert struct {
	ID              string
	Time            time.Time
	RuleName        string
	Severity        int
	SourceIP        string
	Technique       string
	Tactic          string
	Label           string
	Original        string
	Country         string
	AbuseConfidence *int
	OTXPulseCount   *int
}

// AlertsForLLM returns labeled alerts that do not yet have an LLM verdict, newest first.
func (s *Store) AlertsForLLM(ctx context.Context, limit int) ([]LLMAlert, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, time, COALESCE(rule_name,''), COALESCE(event_severity,0),
		       COALESCE(host(source_ip),''), COALESCE(threat_technique_id,''),
		       COALESCE(threat_tactic_name,''), COALESCE(dw_label,''),
		       COALESCE(event_original,''), COALESCE(source_geo_country_iso,''),
		       dw_enrichment_abuse_confidence, dw_enrichment_otx_pulse_count
		FROM events
		WHERE dw_label IS NOT NULL AND dw_llm_verdict IS NULL
		ORDER BY time DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: alerts for llm: %w", err)
	}
	defer rows.Close()

	var out []LLMAlert
	for rows.Next() {
		var a LLMAlert
		if err := rows.Scan(&a.ID, &a.Time, &a.RuleName, &a.Severity, &a.SourceIP,
			&a.Technique, &a.Tactic, &a.Label, &a.Original, &a.Country,
			&a.AbuseConfidence, &a.OTXPulseCount); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetLLMVerdict stores the LLM verdict + summary for one alert.
func (s *Store) SetLLMVerdict(ctx context.Context, id, verdict, summary string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE events SET dw_llm_verdict = $2, dw_llm_summary = $3, dw_llm_analyzed_at = now()
		 WHERE id = $1`, id, verdict, strOrNil(summary))
	if err != nil {
		return fmt.Errorf("store: set llm verdict: %w", err)
	}
	return nil
}
