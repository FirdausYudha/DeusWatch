package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"deuswatch/internal/compliance"
)

// Every gatherer, actually executed.
//
// This test exists because reading the schema was not enough. scan_status was queried for an
// agent_name column it does not have: it is keyed by SCANNER, one row per scanner, so the query
// was wrong about the column AND about the question. The mistake came from trusting a prose
// description of the table instead of its definition, and nothing caught it until the report was
// run against a real database and returned a single line of SQLSTATE 42703.
//
// A column name is not something to verify by reading. Run the query.
func TestEveryEvidenceGathererRuns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable, skipping: %v", err)
	}
	defer st.Close()

	to := time.Now()
	from := to.AddDate(0, 0, -90)

	for _, k := range compliance.Kinds() {
		t.Run(string(k), func(t *testing.T) {
			ev, err := st.gatherEvidence(ctx, k, from, to)
			if err != nil {
				t.Fatalf("gatherer %q failed: %v", k, err)
			}
			// An empty deployment is fine, and every gatherer must still SAY something: a row with
			// no summary is the blank the report promises never to produce.
			if strings.TrimSpace(ev.Summary) == "" {
				t.Errorf("gatherer %q produced no summary", k)
			}
			if ev.Gap && strings.TrimSpace(ev.Why) == "" {
				t.Errorf("gatherer %q reported a gap with no guidance on what to check", k)
			}
		})
	}
}

// The whole report, end to end, against a real database.
func TestISO27001EvidenceBuilds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable, skipping: %v", err)
	}
	defer st.Close()

	rep, err := st.ISO27001Evidence(ctx, time.Now().AddDate(0, 0, -90), time.Now())
	if err != nil {
		t.Fatalf("report failed: %v", err)
	}
	if len(rep.Controls) != len(compliance.Controls) {
		t.Errorf("got %d controls, want %d: every catalogue entry must appear, including the empty ones",
			len(rep.Controls), len(compliance.Controls))
	}
	if rep.Disclaimer == "" || len(rep.NotCovered) == 0 {
		t.Error("the report must carry its disclaimer and its boundary")
	}
	for _, c := range rep.Controls {
		if c.ID == "" || c.Title == "" || c.Summary == "" {
			t.Errorf("incomplete control row: %+v", c)
		}
		// The defect text a failed gatherer produces must never reach a real deployment's report.
		if strings.Contains(c.Why, "DeusWatch defect") {
			t.Errorf("%s could not be gathered, which is a bug in the query: %s", c.ID, c.Why)
		}
	}
}

// One broken gatherer must cost one row, not the report. Before this, a wrong column name
// returned a bare error and took fifteen working controls down with it, leaving the operator with
// a single line of SQLSTATE and no way to tell which control was at fault.
func TestABrokenGathererDegradesToOneRow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable, skipping: %v", err)
	}
	defer st.Close()

	// An unknown kind stands in for a gatherer whose query no longer matches the schema: the
	// caller's job is the same either way, which is to keep going.
	ev, err := st.gatherEvidence(ctx, compliance.Kind("no-such-kind"), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("an unknown kind must not be an error: %v", err)
	}
	if !ev.Gap {
		t.Error("an unknown kind must be reported as a gap")
	}
	if !strings.Contains(ev.Why, "defect in DeusWatch") {
		t.Errorf("the row must say the fault is ours, not the deployment's: %s", ev.Why)
	}
}
