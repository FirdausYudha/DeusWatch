package store

// M3 performance scorecard (Kartu Kinerja).
//
// Eight indicators, each given a predicate (Efektif / Cukup / Perlu Perbaikan) against a fixed
// threshold seeded in scorecard_thresholds, grouped by NIST CSF function. The predicate logic here
// is a pure function so it can be tested at every band boundary without a database; the SQL below
// only gathers the raw numbers.
//
// An indicator with no data is reported as such (Value nil, no predicate) and left out of the
// overall average rather than counted as a zero, because "we never measured this" and "we measured
// zero" are different findings and collapsing them would quietly drag the whole card down.

import (
	"context"
	"fmt"
	"log"
	"time"
)

// Predicate labels, kept as constants so the UI and the tests cannot drift from the store.
const (
	PredEffective  = "Effective"
	PredSufficient = "Adequate"
	PredNeedsWork  = "Needs Improvement"
)

// Indicator is one computed row of the scorecard.
type Indicator struct {
	Key       string   `json:"key"`
	CSF       string   `json:"csf_function"`
	Label     string   `json:"label"`
	Unit      string   `json:"unit"`
	Value     *float64 `json:"value"`     // nil = no data
	Predicate string   `json:"predicate"` // "" when no data
	Note      string   `json:"note,omitempty"`
}

// Extra is a figure shown without a predicate (attack frequency, IPs blocked).
type Extra struct {
	Key   string  `json:"key"`
	Label string  `json:"label"`
	Value float64 `json:"value"`
}

// Scorecard is the whole card for one window.
type Scorecard struct {
	SinceDays         int         `json:"since_days"`
	Indicators        []Indicator `json:"indicators"`
	Extras            []Extra     `json:"extras"`
	Overall           string      `json:"overall_predicate"` // "" when nothing computed
	OverallScore      *float64    `json:"overall_score"`     // mean predicate score, nil when nothing computed
	IndicatorsCounted int         `json:"indicators_counted"`
	IndicatorsTotal   int         `json:"indicators_total"`
}

// threshold is one seeded predicate band.
type threshold struct {
	Key, CSF, Label, Unit string
	HigherIsBetter        bool
	Effective, Sufficient float64
	Sort                  int
}

// predicateFor maps a value to its predicate band. Pure: no I/O, so every boundary is unit-tested.
//
// higherIsBetter: value >= effective is Efektif, >= sufficient is Cukup, else Perlu Perbaikan.
// Otherwise (lower is better): value <= effective is Efektif, <= sufficient is Cukup, else Perlu
// Perbaikan. Boundaries are inclusive on the better side, matching the field table ("≥ 95%",
// "≤ 5 menit").
func predicateFor(value float64, higherIsBetter bool, effective, sufficient float64) string {
	if higherIsBetter {
		switch {
		case value >= effective:
			return PredEffective
		case value >= sufficient:
			return PredSufficient
		default:
			return PredNeedsWork
		}
	}
	switch {
	case value <= effective:
		return PredEffective
	case value <= sufficient:
		return PredSufficient
	default:
		return PredNeedsWork
	}
}

// predicateScore turns a predicate into its numeric weight: Efektif 3, Cukup 2, Perlu Perbaikan 1.
func predicateScore(p string) int {
	switch p {
	case PredEffective:
		return 3
	case PredSufficient:
		return 2
	case PredNeedsWork:
		return 1
	}
	return 0
}

// overallPredicate averages the per-indicator scores and bands the mean: >= 2.50 Efektif,
// >= 1.75 Cukup, else Perlu Perbaikan. Returns ("", nil) when no indicator had data, so the caller
// shows "belum ada data" instead of inventing a verdict from nothing.
func overallPredicate(scores []int) (string, *float64) {
	if len(scores) == 0 {
		return "", nil
	}
	sum := 0
	for _, s := range scores {
		sum += s
	}
	mean := float64(sum) / float64(len(scores))
	var pred string
	switch {
	case mean >= 2.50:
		pred = PredEffective
	case mean >= 1.75:
		pred = PredSufficient
	default:
		pred = PredNeedsWork
	}
	return pred, &mean
}

// loadThresholds reads the seeded predicate bands, ordered for display.
func (s *Store) loadThresholds(ctx context.Context) ([]threshold, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT indicator_key, csf_function, label, unit, higher_is_better, effective, sufficient, sort_order
		  FROM scorecard_thresholds ORDER BY sort_order`)
	if err != nil {
		return nil, fmt.Errorf("store: load thresholds: %w", err)
	}
	defer rows.Close()
	var out []threshold
	for rows.Next() {
		var t threshold
		if err := rows.Scan(&t.Key, &t.CSF, &t.Label, &t.Unit, &t.HigherIsBetter,
			&t.Effective, &t.Sufficient, &t.Sort); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Scorecard computes every indicator for the last `days` days and bands each one.
func (s *Store) Scorecard(ctx context.Context, days int) (*Scorecard, error) {
	if days <= 0 || days > 365 {
		days = 30
	}
	since := time.Now().AddDate(0, 0, -days)

	ths, err := s.loadThresholds(ctx)
	if err != nil {
		return nil, err
	}

	// Gather raw values (nil = no data) and per-indicator notes. Each indicator query is isolated,
	// so one failing query leaves that indicator as no-data rather than failing the whole scorecard.
	vals := map[string]*float64{}
	notes := map[string]string{}
	s.scorecardValues(ctx, since, vals, notes)

	out := &Scorecard{SinceDays: days, Indicators: []Indicator{}, Extras: []Extra{}}
	var scores []int
	for _, t := range ths {
		ind := Indicator{Key: t.Key, CSF: t.CSF, Label: t.Label, Unit: t.Unit, Note: notes[t.Key]}
		if v := vals[t.Key]; v != nil {
			ind.Value = v
			ind.Predicate = predicateFor(*v, t.HigherIsBetter, t.Effective, t.Sufficient)
			scores = append(scores, predicateScore(ind.Predicate))
		} else if ind.Note == "" {
			ind.Note = "no data yet"
		}
		out.Indicators = append(out.Indicators, ind)
	}
	out.IndicatorsTotal = len(ths)
	out.IndicatorsCounted = len(scores)
	out.Overall, out.OverallScore = overallPredicate(scores)

	// Extras, shown without a predicate.
	s.scorecardExtras(ctx, since, out)
	return out, nil
}

// scorecardValues fills vals/notes for every indicator. A nil entry (or an absent key) means the
// indicator has no data for this window.
func (s *Store) scorecardValues(ctx context.Context, since time.Time, vals map[string]*float64, notes map[string]string) {
	q := s.q(ctx)
	try := s.indicatorRunner(ctx, q)

	// source_coverage: active agents / registered agents * 100.
	// shortcut: agent-based; switch to a data-source registry when P1-6 (data_sources) is built.
	try("source_coverage", func() error {
		var active, registered int
		if err := q.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE status = 'online' AND NOT revoked),
			       count(*) FILTER (WHERE NOT revoked)
			  FROM agents`).Scan(&active, &registered); err != nil {
			return err
		}
		if registered > 0 {
			v := 100.0 * float64(active) / float64(registered)
			vals["source_coverage"] = &v
			notes["source_coverage"] = fmt.Sprintf("%d of %d agents active", active, registered)
		}
		return nil
	})

	// detection_rate: scenarios detected on ALL their repetitions / 13 * 100. A scenario with no
	// recorded run counts as not detected, so the denominator is always the full 13.
	try("detection_rate", func() error {
		var allDetected int
		if err := q.QueryRow(ctx, `
			SELECT count(*) FROM (
			   SELECT scenario_id FROM scenario_runs
			    GROUP BY scenario_id
			   HAVING count(*) > 0 AND bool_and(detected)
			) x`).Scan(&allDetected); err != nil {
			return err
		}
		v := 100.0 * float64(allDetected) / 13.0
		vals["detection_rate"] = &v
		notes["detection_rate"] = fmt.Sprintf("%d of 13 scenarios detected on every repetition", allDetected)
		return nil
	})

	// mttd: median detection latency over REAL alerts in the window - how long after the activity
	// (event.time) the alert was ingested (ingested_at, migration 000087). This is the live signal,
	// not the imported controlled-test log. Rows before the column existed are NULL and excluded,
	// and the ingested_at >= time guard drops agent-clock skew that would otherwise read negative.
	try("mttd", func() error {
		var v *float64
		if err := q.QueryRow(ctx, `
			SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (ingested_at - time))/60.0)
			   FROM events
			  WHERE dw_label <> '' AND ingested_at IS NOT NULL AND ingested_at >= time AND time >= $1`, since).Scan(&v); err != nil {
			return err
		}
		vals["mttd"] = v
		notes["mttd"] = "from live alerts (ingest time minus occurrence time)"
		return nil
	})

	// mttr: median time to respond, from the REAL ticket queue - created (~alert time) to acked
	// (someone started handling it). A recommendation still awaiting approval has no ticket ack, so
	// it is not counted, which matches the field definition of MTTR.
	try("mttr", func() error {
		var v *float64
		if err := q.QueryRow(ctx, `
			SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (acked_at - created_at))/60.0)
			   FROM tickets WHERE acked_at IS NOT NULL AND created_at >= $1`, since).Scan(&v); err != nil {
			return err
		}
		vals["mttr"] = v
		notes["mttr"] = "from the ticket queue (acknowledged time minus created time)"
		return nil
	})

	// benchmark_score: CIS passed / evaluable (passed+failed) * 100, averaged per host.
	try("benchmark", func() error {
		var v *float64
		if err := q.QueryRow(ctx, `
			SELECT avg(host_pct) FROM (
			   SELECT 100.0 * count(*) FILTER (WHERE result = 'passed')
			        / NULLIF(count(*) FILTER (WHERE result IN ('passed','failed')), 0) AS host_pct
			     FROM agent_benchmarks GROUP BY agent_name
			) h WHERE host_pct IS NOT NULL`).Scan(&v); err != nil {
			return err
		}
		vals["benchmark_score"] = v
		return nil
	})

	// false_positive_ratio: alerts flagged false positive / reviewed alerts * 100.
	try("false_positive", func() error {
		var fp, reviewed int
		if err := q.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE false_positive), count(*) FROM alert_reviews`).Scan(&fp, &reviewed); err != nil {
			return err
		}
		if reviewed > 0 {
			v := 100.0 * float64(fp) / float64(reviewed)
			vals["false_positive_ratio"] = &v
			notes["false_positive_ratio"] = fmt.Sprintf("%d of %d alerts reviewed", fp, reviewed)
		}
		return nil
	})

	// bridging_detection: S11 reps alerting within 5 min of the fault / total S11 reps * 100.
	try("bridging", func() error {
		var within, total int
		if err := q.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE detected AND alerted_at IS NOT NULL AND executed_at IS NOT NULL
			                          AND alerted_at - executed_at <= interval '5 minutes'),
			       count(*)
			  FROM scenario_runs WHERE scenario_id = 'S11'`).Scan(&within, &total); err != nil {
			return err
		}
		if total > 0 {
			v := 100.0 * float64(within) / float64(total)
			vals["bridging_detection"] = &v
			notes["bridging_detection"] = fmt.Sprintf("%d of %d S11 repetitions within 5 minutes", within, total)
		}
		return nil
	})

	// report_prep_time: most recent manual figure, in days. Wrapped in a subquery so it always
	// returns one row (NULL when none), rather than ErrNoRows.
	try("report_prep", func() error {
		var v *float64
		if err := q.QueryRow(ctx, `
			SELECT (SELECT value FROM scorecard_inputs WHERE input_key = 'report_prep_time'
			         ORDER BY recorded_at DESC LIMIT 1)`).Scan(&v); err != nil {
			return err
		}
		vals["report_prep_time"] = v
		return nil
	})
}

// indicatorRunner returns a helper that runs each indicator query isolated by a SAVEPOINT, so a
// single failing query (a missing column on an older schema, an optional table, a permission) rolls
// back only itself and the scorecard transaction stays usable for the next indicator - one broken
// indicator must not blank the whole card. Outside a transaction the SAVEPOINT errors harmlessly
// and is skipped (a pooled query auto-commits, so a failure is already isolated). A failed
// indicator is logged and simply left as no-data.
func (s *Store) indicatorRunner(ctx context.Context, q Queryer) func(string, func() error) {
	return func(name string, fn func() error) {
		sp := false
		if _, err := q.Exec(ctx, "SAVEPOINT scard_sp"); err == nil {
			sp = true
		}
		if err := fn(); err != nil {
			if sp {
				_, _ = q.Exec(ctx, "ROLLBACK TO SAVEPOINT scard_sp")
			}
			log.Printf("store: scorecard %s: %v", name, err)
			return
		}
		if sp {
			_, _ = q.Exec(ctx, "RELEASE SAVEPOINT scard_sp")
		}
	}
}

// scorecardExtras fills the no-predicate figures: how often attacks fired and how many IPs were
// blocked in the window.
func (s *Store) scorecardExtras(ctx context.Context, since time.Time, out *Scorecard) {
	q := s.q(ctx)
	try := s.indicatorRunner(ctx, q)
	try("attack_frequency", func() error {
		var attacks int
		if err := q.QueryRow(ctx,
			`SELECT count(*) FROM events WHERE dw_label <> '' AND time >= $1`, since).Scan(&attacks); err != nil {
			return err
		}
		out.Extras = append(out.Extras, Extra{Key: "attack_frequency", Label: "Attack frequency (alerts)", Value: float64(attacks)})
		return nil
	})
	try("ips_blocked", func() error {
		var ips int
		if err := q.QueryRow(ctx,
			`SELECT count(DISTINCT ip) FROM containment_actions WHERE ip IS NOT NULL AND created_at >= $1`,
			since).Scan(&ips); err != nil {
			return err
		}
		out.Extras = append(out.Extras, Extra{Key: "ips_blocked", Label: "IPs blocked", Value: float64(ips)})
		return nil
	})
}
