package tickets

import (
	"context"
	"fmt"
	"time"
)

// SLA scorecard.
//
// The hospital IT team judges itself on its ticket queue: "jamnya awalnya ini masuk, nanti
// penyelesaiannya kayak gimana. Nanti bisa jadi rapot." So this answers two questions, kept
// separate on purpose:
//
//   - Response — how long until somebody picked it up. This is the half that says whether the team
//     is responsive.
//   - Resolution — how long until it was actually finished.
//
// A team can be fast at one and slow at the other, and collapsing them into a single "average
// handling time" hides exactly the problem a scorecard is for.
//
// Medians and p90s, never means. One ticket left open over a long weekend drags a mean so far that
// the number stops describing anything; the p90 answers "how bad is a bad week" without letting a
// single outlier speak for the month.

// Duration stats for one population of tickets, in seconds. Nil means no ticket in this population
// reached that milestone — which is itself a finding, not a zero.
type Durations struct {
	P50 *float64 `json:"p50_secs"`
	P90 *float64 `json:"p90_secs"`
}

// SLAStats is the whole scorecard for one window.
type SLAStats struct {
	SinceDays int `json:"since_days"`

	Total       int `json:"total"`
	AutoCreated int `json:"auto_created"`
	StillOpen   int `json:"still_open"`
	Resolved    int `json:"resolved"`
	// NeverAcked counts live tickets nobody has touched at all. The single most useful number on
	// the page: it is the queue that is being ignored right now, as opposed to the one running late.
	NeverAcked int `json:"never_acked"`

	Response   Durations `json:"response"`
	Resolution Durations `json:"resolution"`

	BySeverity []SLABucket `json:"by_severity"`
	ByAssignee []SLABucket `json:"by_assignee"`
}

// SLABucket is one row of a breakdown.
type SLABucket struct {
	Key        string    `json:"key"`
	Total      int       `json:"total"`
	Resolved   int       `json:"resolved"`
	Response   Durations `json:"response"`
	Resolution Durations `json:"resolution"`
}

// The two measurements, as SQL. Response is created→acked; resolution is created→resolved. Both
// are FILTERed so a ticket that never reached the milestone is left out of the percentile rather
// than counted as instant or as infinitely slow.
const slaDurationCols = `
	percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (acked_at - created_at)))
		FILTER (WHERE acked_at IS NOT NULL),
	percentile_cont(0.9) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (acked_at - created_at)))
		FILTER (WHERE acked_at IS NOT NULL),
	percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (resolved_at - created_at)))
		FILTER (WHERE resolved_at IS NOT NULL),
	percentile_cont(0.9) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (resolved_at - created_at)))
		FILTER (WHERE resolved_at IS NOT NULL)`

// SLAScorecard computes the scorecard over the last `days` days.
func (s *Store) SLAScorecard(ctx context.Context, days int) (*SLAStats, error) {
	if days <= 0 || days > 365 {
		days = 30
	}
	since := time.Now().AddDate(0, 0, -days)
	out := &SLAStats{SinceDays: days, BySeverity: []SLABucket{}, ByAssignee: []SLABucket{}}

	err := s.q(ctx).QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE auto_created),
		       count(*) FILTER (WHERE status IN ('open','in_progress')),
		       count(*) FILTER (WHERE resolved_at IS NOT NULL),
		       count(*) FILTER (WHERE acked_at IS NULL AND status IN ('open','in_progress')),`+
		slaDurationCols+`
		  FROM tickets WHERE created_at >= $1`, since).
		Scan(&out.Total, &out.AutoCreated, &out.StillOpen, &out.Resolved, &out.NeverAcked,
			&out.Response.P50, &out.Response.P90, &out.Resolution.P50, &out.Resolution.P90)
	if err != nil {
		return nil, fmt.Errorf("tickets: sla scorecard: %w", err)
	}

	// Severity sorts correctly as text here because the values are the single digits 0..4.
	if out.BySeverity, err = s.slaBuckets(ctx, since, `severity::text`); err != nil {
		return nil, err
	}
	// Attributed to whoever picked it up, not to the current assignee: reassigning a finished
	// ticket must not move its response time onto somebody who was not there.
	if out.ByAssignee, err = s.slaBuckets(ctx, since,
		`COALESCE(NULLIF(acked_by,''), '(unassigned)')`); err != nil {
		return nil, err
	}
	return out, nil
}

// slaBuckets runs the scorecard grouped by one expression. keyExpr is a literal from the call
// sites above, never user input.
func (s *Store) slaBuckets(ctx context.Context, since time.Time, keyExpr string) ([]SLABucket, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT `+keyExpr+` AS k,
		       count(*),
		       count(*) FILTER (WHERE resolved_at IS NOT NULL),`+
		slaDurationCols+`
		  FROM tickets WHERE created_at >= $1
		 GROUP BY `+keyExpr+`
		 ORDER BY 1`, since)
	if err != nil {
		return nil, fmt.Errorf("tickets: sla breakdown: %w", err)
	}
	defer rows.Close()

	out := make([]SLABucket, 0, 8)
	for rows.Next() {
		var b SLABucket
		if err := rows.Scan(&b.Key, &b.Total, &b.Resolved,
			&b.Response.P50, &b.Response.P90, &b.Resolution.P50, &b.Resolution.P90); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
