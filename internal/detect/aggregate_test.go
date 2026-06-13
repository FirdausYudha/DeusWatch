package detect

import (
	"context"
	"testing"
	"time"

	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/ingest"
)

// fakeAgg memenuhi AggExecutor: mengembalikan grup yang sudah ditentukan dan
// mencatat berapa kali dipanggil.
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
		if r.GroupByField == "source.ip" && r.Op == ">" {
			return r
		}
	}
	t.Fatal("rule agregasi brute-force tak ditemukan")
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
		t.Fatalf("harap 1 alert, dapat %d", len(alerts))
	}
	a := alerts[0]
	if a.Source == nil || a.Source.IP != "203.0.113.7" {
		t.Fatalf("source IP grup tak terbawa: %+v", a.Source)
	}
	if a.Event.Severity != ingest.SeverityHigh {
		t.Fatalf("severity salah: %v", a.Event.Severity)
	}
	if a.Threat.Technique.ID != "T1110" {
		t.Fatalf("MITRE salah: %q", a.Threat.Technique.ID)
	}
	if a.Rule == nil || a.Rule.ID == "" {
		t.Fatal("alert tanpa rule id")
	}
}

func TestAggregateRunnerCooldown(t *testing.T) {
	rule := loadBruteForceAgg(t)
	exec := &fakeAgg{groups: []AggGroup{{Group: "10.0.0.9", Count: 9, LastSeen: time.Now()}}}
	r := NewAggregateRunner(exec, []*sigma.AggRule{rule}, 5*time.Minute)

	now := time.Now()
	if a, _ := r.RunOnce(context.Background(), now); len(a) != 1 {
		t.Fatalf("siklus 1 harus 1 alert, dapat %d", len(a))
	}
	// Dalam cooldown: grup yang sama tak boleh memicu lagi.
	if a, _ := r.RunOnce(context.Background(), now.Add(time.Minute)); len(a) != 0 {
		t.Fatalf("dalam cooldown tak boleh ada alert, dapat %d", len(a))
	}
	// Setelah cooldown: memicu lagi.
	if a, _ := r.RunOnce(context.Background(), now.Add(6*time.Minute)); len(a) != 1 {
		t.Fatalf("setelah cooldown harus memicu lagi, dapat %d", len(a))
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
		t.Fatalf("dry-run harus mengembalikan 2 grup, dapat %d", len(groups))
	}
	// Dry-run tak boleh mengubah state cooldown.
	if a, _ := r.RunOnce(context.Background(), time.Now()); len(a) != 2 {
		t.Fatalf("dry-run tak boleh konsumsi cooldown; harap 2 alert, dapat %d", len(a))
	}
}
