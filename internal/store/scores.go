package store

import (
	"context"
	"fmt"
	"time"

	"deuswatch/internal/score"
)

// IPScore is a stored composite score for one source IP.
type IPScore struct {
	IP         string    `json:"ip"`
	Score      int       `json:"score"`
	Band       string    `json:"band"`
	FiredTimes int       `json:"fired_times"`
	Abuse      int       `json:"abuse"`
	OTX        int       `json:"otx"`
	MaxSev     int       `json:"max_sev"`
	Anomaly    int       `json:"anomaly"` // ML anomaly_score folded into the composite score
	Agents     int       `json:"agents"`  // distinct endpoints this IP touched (cross-agent fan-out)
	UpdatedAt  time.Time `json:"updated_at"`
}

// RefreshIPScores recomputes the composite score for every source IP seen within `window`
// and upserts ip_scores. IPs not seen in the window are pruned so stale scores fade out.
// Returns the scored rows (highest first) so a caller can drive a scenario ban.
func (s *Store) RefreshIPScores(ctx context.Context, window time.Duration, w score.Weights) ([]IPScore, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT host(e.source_ip)                                AS ip,
		       count(*)                                         AS fired_times,
		       COALESCE(max(e.dw_enrichment_abuse_confidence),0) AS abuse,
		       COALESCE(max(e.dw_enrichment_otx_pulse_count),0)  AS otx,
		       COALESCE(max(e.event_severity),0)                AS max_sev,
		       COALESCE(max(an.anomaly),0)                      AS anomaly,
		       count(DISTINCT e.agent_id) FILTER (WHERE e.agent_id IS NOT NULL AND e.agent_id <> '') AS agents
		FROM events e LEFT JOIN ip_anomaly an ON an.ip = e.source_ip
		WHERE e.source_ip IS NOT NULL AND e.time > now() - $1::interval
		GROUP BY e.source_ip`, fmt.Sprintf("%d seconds", int(window.Seconds())))
	if err != nil {
		return nil, fmt.Errorf("store: score query: %w", err)
	}
	defer rows.Close()

	var out []IPScore
	for rows.Next() {
		var r IPScore
		if err := rows.Scan(&r.IP, &r.FiredTimes, &r.Abuse, &r.OTX, &r.MaxSev, &r.Anomaly, &r.Agents); err != nil {
			return nil, err
		}
		res := score.Compute(score.Signals{
			FiredTimes: r.FiredTimes, Abuse: r.Abuse, OTX: r.OTX, MaxSeverity: r.MaxSev,
			Anomaly: r.Anomaly, Agents: r.Agents,
		}, w)
		r.Score, r.Band = res.Score, res.Band
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Upsert current scores; prune IPs that dropped out of the window.
	batch := make([][]any, 0, len(out))
	for _, r := range out {
		batch = append(batch, []any{r.IP, r.Score, r.Band, r.FiredTimes, r.Abuse, r.OTX, r.MaxSev, r.Anomaly, r.Agents})
	}
	for _, b := range batch {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO ip_scores (ip, score, band, fired_times, abuse, otx, max_sev, anomaly, agents, updated_at)
			VALUES ($1::inet,$2,$3,$4,$5,$6,$7,$8,$9, now())
			ON CONFLICT (ip) DO UPDATE SET
			  score=EXCLUDED.score, band=EXCLUDED.band, fired_times=EXCLUDED.fired_times,
			  abuse=EXCLUDED.abuse, otx=EXCLUDED.otx, max_sev=EXCLUDED.max_sev,
			  anomaly=EXCLUDED.anomaly, agents=EXCLUDED.agents, updated_at=now()`,
			b...); err != nil {
			return nil, fmt.Errorf("store: score upsert: %w", err)
		}
	}
	// Prune scores older than 2x the window (IP no longer active).
	_, _ = s.pool.Exec(ctx, `DELETE FROM ip_scores WHERE updated_at < now() - $1::interval`,
		fmt.Sprintf("%d seconds", int(2*window.Seconds())))
	return out, nil
}

// IPScoresFor returns the current scores for the given IPs (for the Events/Alerts table).
func (s *Store) IPScoresFor(ctx context.Context, ips []string) (map[string]IPScore, error) {
	out := map[string]IPScore{}
	if len(ips) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT host(ip), score, band FROM ip_scores WHERE host(ip) = ANY($1)`, ips)
	if err != nil {
		return nil, fmt.Errorf("store: scores for: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r IPScore
		if err := rows.Scan(&r.IP, &r.Score, &r.Band); err != nil {
			return nil, err
		}
		out[r.IP] = r
	}
	return out, rows.Err()
}

// TopIPScores returns the highest-scoring IPs (for a dashboard widget / report).
func (s *Store) TopIPScores(ctx context.Context, limit int) ([]IPScore, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx,
		`SELECT host(ip), score, band, fired_times, abuse, otx, max_sev, COALESCE(agents,0), updated_at
		 FROM ip_scores ORDER BY score DESC, updated_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: top scores: %w", err)
	}
	defer rows.Close()
	var out []IPScore
	for rows.Next() {
		var r IPScore
		if err := rows.Scan(&r.IP, &r.Score, &r.Band, &r.FiredTimes, &r.Abuse, &r.OTX, &r.MaxSev, &r.Agents, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
