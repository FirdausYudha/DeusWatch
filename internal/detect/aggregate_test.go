package detect

import (
	"context"
	"strings"
	"testing"
	"time"

	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/ingest"
)

// fakeAgg satisfies AggExecutor: returns predetermined groups and records how many
// times it was called.
type fakeAgg struct {
	groups []AggGroup
	calls  int
}

func (f *fakeAgg) QueryAgg(_ context.Context, _ string, _ []any) ([]AggGroup, error) {
	f.calls++
	return f.groups, nil
}

func loadBruteForceAgg(t *testing.T) *sigma.AggRule {
	t.Helper()
	rules, err := sigma.LoadAggDir("../../rules/sigma")
	if err != nil {
		t.Fatalf("LoadAggDir: %v", err)
	}
	for _, r := range rules {
		// Select the SSH rule specifically (several rules now group by source.ip).
		if strings.Contains(r.Title, "SSH Brute Force") {
			return r
		}
	}
	t.Fatal("brute-force aggregation rule not found")
	return nil
}

func TestAggregateRunnerEmitsAlert(t *testing.T) {
	rule := loadBruteForceAgg(t)
	exec := &fakeAgg{groups: []AggGroup{
		{Group: "203.0.113.7", Count: 12, LastSeen: time.Now()},
	}}
	r := NewAggregateRunner(exec, []*sigma.AggRule{rule}, time.Minute)

	alerts, err := r.RunOnce(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.Source == nil || a.Source.IP != "203.0.113.7" {
		t.Fatalf("group source IP not carried over: %+v", a.Source)
	}
	if a.Event.Severity != ingest.SeverityHigh {
		t.Fatalf("wrong severity: %v", a.Event.Severity)
	}
	if a.Threat.Technique.ID != "T1110" {
		t.Fatalf("wrong MITRE: %q", a.Threat.Technique.ID)
	}
	if a.Rule == nil || a.Rule.ID == "" {
		t.Fatal("alert without a rule id")
	}
}

func TestAggregateRunnerCooldown(t *testing.T) {
	rule := loadBruteForceAgg(t)
	exec := &fakeAgg{groups: []AggGroup{{Group: "10.0.0.9", Count: 9, LastSeen: time.Now()}}}
	r := NewAggregateRunner(exec, []*sigma.AggRule{rule}, 5*time.Minute)

	now := time.Now()
	if a, _ := r.RunOnce(context.Background(), now); len(a) != 1 {
		t.Fatalf("cycle 1 must be 1 alert, got %d", len(a))
	}
	// Within cooldown: the same group must not trigger again.
	if a, _ := r.RunOnce(context.Background(), now.Add(time.Minute)); len(a) != 0 {
		t.Fatalf("within cooldown there must be no alert, got %d", len(a))
	}
	// After cooldown: triggers again.
	if a, _ := r.RunOnce(context.Background(), now.Add(6*time.Minute)); len(a) != 1 {
		t.Fatalf("after cooldown it must trigger again, got %d", len(a))
	}
}

func TestAggregateRunnerDryRun(t *testing.T) {
	rule := loadBruteForceAgg(t)
	exec := &fakeAgg{groups: []AggGroup{
		{Group: "1.1.1.1", Count: 20},
		{Group: "2.2.2.2", Count: 7},
	}}
	r := NewAggregateRunner(exec, []*sigma.AggRule{rule}, time.Minute)

	groups, err := r.DryRun(context.Background(), rule)
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("dry-run must return 2 groups, got %d", len(groups))
	}
	// Dry-run must not change cooldown state.
	if a, _ := r.RunOnce(context.Background(), time.Now()); len(a) != 2 {
		t.Fatalf("dry-run must not consume cooldown; expected 2 alerts, got %d", len(a))
	}
}
