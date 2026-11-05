package store

import (
	"context"
	"testing"
	"time"
)

// predicateFor and overallPredicate are the whole judgement of the scorecard, so every band
// boundary is pinned here. Pure functions: no database needed.
func TestPredicateForHigherIsBetter(t *testing.T) {
	// source_coverage style: effective 95, sufficient 80, higher is better.
	cases := []struct {
		v    float64
		want string
	}{
		{100, PredEffective},
		{95, PredEffective},   // boundary, inclusive
		{94.9, PredSufficient},
		{80, PredSufficient},  // boundary, inclusive
		{79.9, PredNeedsWork},
		{0, PredNeedsWork},
	}
	for _, c := range cases {
		if got := predicateFor(c.v, true, 95, 80); got != c.want {
			t.Errorf("predicateFor(%v, higher, 95, 80) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestPredicateForLowerIsBetter(t *testing.T) {
	// mttd style: effective 5, sufficient 15, lower is better.
	cases := []struct {
		v    float64
		want string
	}{
		{0, PredEffective},
		{5, PredEffective},    // boundary, inclusive
		{5.1, PredSufficient},
		{15, PredSufficient},  // boundary, inclusive
		{15.1, PredNeedsWork},
		{60, PredNeedsWork},
	}
	for _, c := range cases {
		if got := predicateFor(c.v, false, 5, 15); got != c.want {
			t.Errorf("predicateFor(%v, lower, 5, 15) = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestOverallPredicate(t *testing.T) {
	cases := []struct {
		name   string
		scores []int
		want   string
		hasVal bool
	}{
		{"all effective", []int{3, 3, 3}, PredEffective, true},
		{"mean 2.50 boundary -> Efektif", []int{3, 2}, PredEffective, true},
		{"mean 2.33 -> Cukup", []int{3, 2, 2}, PredSufficient, true},
		{"mean 1.75 boundary -> Cukup", []int{2, 2, 1, 2}, PredSufficient, true},
		{"mean 1.67 -> Perlu Perbaikan", []int{2, 2, 1}, PredNeedsWork, true},
		{"all needs work", []int{1, 1}, PredNeedsWork, true},
		{"no data", nil, "", false},
	}
	for _, c := range cases {
		got, score := overallPredicate(c.scores)
		if got != c.want {
			t.Errorf("%s: overall = %q, want %q", c.name, got, c.want)
		}
		if (score != nil) != c.hasVal {
			t.Errorf("%s: score present = %v, want %v", c.name, score != nil, c.hasVal)
		}
	}
}

func TestPredicateScore(t *testing.T) {
	if predicateScore(PredEffective) != 3 || predicateScore(PredSufficient) != 2 ||
		predicateScore(PredNeedsWork) != 1 || predicateScore("") != 0 {
		t.Fatal("predicateScore mapping wrong")
	}
}

// TestScorecardComputes checks the whole card computes against a real Postgres without failing,
// exercising the per-indicator savepoint isolation. Integration, skipped if Postgres is down.
func TestScorecardComputes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := ConnectSuperadmin(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable, skipping: %v", err)
	}
	defer st.Close()

	card, err := st.Scorecard(ctx, 30)
	if err != nil {
		t.Fatalf("Scorecard returned an error (should degrade per-indicator, not fail): %v", err)
	}
	if card.IndicatorsTotal != 8 {
		t.Fatalf("expected 8 indicators, got %d", card.IndicatorsTotal)
	}
	// Every indicator with a value must carry one of the three valid predicates; a nil-value one
	// must carry none.
	valid := map[string]bool{PredEffective: true, PredSufficient: true, PredNeedsWork: true}
	for _, ind := range card.Indicators {
		if ind.Value != nil && !valid[ind.Predicate] {
			t.Fatalf("indicator %q has a value but invalid predicate %q", ind.Key, ind.Predicate)
		}
		if ind.Value == nil && ind.Predicate != "" {
			t.Fatalf("indicator %q has no value but a predicate %q", ind.Key, ind.Predicate)
		}
	}
}

// TestScorecardMedianAndImport exercises the SQL median (MTTD) and the CSV import against a real
// Postgres. Integration, skipped if Postgres is down. Self-cleaning: it only touches rows whose
// scenario id starts with the ZT test prefix.
func TestScorecardMedianAndImport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := ConnectSuperadmin(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable, skipping: %v", err)
	}
	defer st.Close()

	clean := func() { _, _ = st.pool.Exec(ctx, `DELETE FROM scenario_runs WHERE scenario_id LIKE 'ZT%'`) }
	clean()
	defer clean()

	// Three ZT reps with alert-minus-execution deltas of 1, 3 and 5 minutes -> median 3 minutes.
	base := time.Now().Add(-time.Hour)
	rows := []struct {
		id        string
		rep       int
		deltaMin  float64
	}{{"ZT1", 1, 1}, {"ZT1", 2, 3}, {"ZT1", 3, 5}}
	for _, r := range rows {
		exec := base
		alert := base.Add(time.Duration(r.deltaMin * float64(time.Minute)))
		if _, err := st.pool.Exec(ctx, `
			INSERT INTO scenario_runs (scenario_id, repetition, executed_at, alerted_at, detected)
			VALUES ($1,$2,$3,$4,true)`, r.id, r.rep, exec, alert); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	var mttd *float64
	if err := st.pool.QueryRow(ctx, `
		SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (alerted_at - executed_at))/60.0)
		  FROM scenario_runs WHERE scenario_id LIKE 'ZT%' AND alerted_at IS NOT NULL`).Scan(&mttd); err != nil {
		t.Fatalf("median query: %v", err)
	}
	if mttd == nil || *mttd < 2.99 || *mttd > 3.01 {
		t.Fatalf("MTTD median = %v, want ~3 minutes", mttd)
	}

	// Import updates in place: re-importing the same key must not duplicate.
	csv := "id_skenario,ulangan,waktu_eksekusi,waktu_alert,waktu_respons,aturan_atau_fitur,teknik,terdeteksi,catatan\n" +
		"ZT9,1,2026-11-05 03:00:00 +0700,2026-11-05 03:00:02 +0700,,uji,T9999,ya,catatan uji\n"
	for i := 0; i < 2; i++ {
		res, err := st.ImportScenarioRuns(ctx, csv)
		if err != nil {
			t.Fatalf("import: %v", err)
		}
		if res.Imported != 1 || len(res.Rejected) != 0 {
			t.Fatalf("import result = %+v, want 1 imported / 0 rejected", res)
		}
	}
	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM scenario_runs WHERE scenario_id='ZT9'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("ZT9 rows = %d, want 1 (upsert, not duplicate)", n)
	}
}
