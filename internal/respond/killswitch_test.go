package respond

import (
	"context"
	"testing"

	"deuswatch/internal/ingest"
)

type fakeKillStore struct {
	calls []map[string]any
}

func (f *fakeKillStore) RecommendKill(ctx context.Context, agentName string, pid int, procName, exe, procStart, reason, requestedBy string, auto bool) error {
	f.calls = append(f.calls, map[string]any{
		"agent": agentName, "pid": pid, "name": procName, "exe": exe,
		"start": procStart, "reason": reason, "auto": auto,
	})
	return nil
}

// encryptionAlert is the strong ransomware signal: the agent measured a text->random entropy jump
// and attributed it to a process.
func encryptionAlert() *ingest.Event {
	e := &ingest.Event{}
	e.Event.Action = "file_encrypted"
	e.Event.Category = "file"
	e.File = &ingest.File{Path: "/srv/data/report.docx"}
	e.Agent = &ingest.Agent{ID: "web01"}
	e.Process = &ingest.Process{Name: "cryptor", PID: 4242, CommandLine: "/tmp/.x/cryptor", Start: "88123"}
	return e
}

// TestKillRecommenderProposesOnEncryption is the happy path - and it must produce a RECOMMENDATION
// (auto=false), never an immediate kill, unless the operator opted in.
func TestKillRecommenderProposesOnEncryption(t *testing.T) {
	f := &fakeKillStore{}
	k := NewKillRecommender(f, false)

	ok, err := k.Evaluate(context.Background(), encryptionAlert())
	if err != nil || !ok {
		t.Fatalf("expected a recommendation, got ok=%v err=%v", ok, err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("expected exactly one recommendation, got %d", len(f.calls))
	}
	c := f.calls[0]
	if c["auto"] != false {
		t.Fatal("a kill must default to recommend-only, awaiting human approval")
	}
	if c["pid"] != 4242 || c["start"] != "88123" {
		t.Fatalf("the process identity must be carried through for verification, got %v", c)
	}
	if c["reason"] == "" {
		t.Fatal("a recommendation must explain itself - an operator cannot approve what it cannot read")
	}
}

// TestKillRecommenderRefusesWithoutAttribution is the core honesty gate: a ransomware alert with no
// attributed process gives nothing safe to act on, so no recommendation may be produced. Without
// this, operators would see kill buttons that can only ever fail.
func TestKillRecommenderRefusesWithoutAttribution(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ingest.Event)
	}{
		{"no process at all (who-data disabled)", func(e *ingest.Event) { e.Process = nil }},
		{"no pid", func(e *ingest.Event) { e.Process.PID = 0 }},
		{"no identity evidence to verify against", func(e *ingest.Event) {
			e.Process.Start, e.Process.CommandLine = "", ""
		}},
		{"no agent to send it to", func(e *ingest.Event) { e.Agent = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeKillStore{}
			k := NewKillRecommender(f, false)
			alert := encryptionAlert()
			tc.mutate(alert)

			ok, err := k.Evaluate(context.Background(), alert)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok || len(f.calls) != 0 {
				t.Fatalf("must not propose a kill it cannot verify; proposed %v", f.calls)
			}
		})
	}
}

// TestKillRecommenderIgnoresOrdinaryAlerts proves the blast radius stays small: routine file
// changes, logins and network alerts must never propose killing a process.
func TestKillRecommenderIgnoresOrdinaryAlerts(t *testing.T) {
	mk := func(action, category string) *ingest.Event {
		e := encryptionAlert()
		e.Event.Action, e.Event.Category = action, category
		return e
	}
	for _, alert := range []*ingest.Event{
		mk("file_modified", "file"),
		mk("file_created", "file"),
		mk("logon_failed", "authentication"),
		mk("connection_attempt", "network"),
	} {
		f := &fakeKillStore{}
		k := NewKillRecommender(f, false)
		if ok, _ := k.Evaluate(context.Background(), alert); ok || len(f.calls) != 0 {
			t.Fatalf("%s must not propose a kill", alert.Event.Action)
		}
	}
}

// TestKillRecommenderAutoModeIsOptIn: with KILL_SWITCH_AUTO the recommendation is queued for
// immediate delivery. The flag must be the ONLY thing that changes this.
func TestKillRecommenderAutoModeIsOptIn(t *testing.T) {
	f := &fakeKillStore{}
	k := NewKillRecommender(f, true)
	if !k.Auto() {
		t.Fatal("Auto() must report the bypass honestly")
	}
	if ok, _ := k.Evaluate(context.Background(), encryptionAlert()); !ok {
		t.Fatal("expected a queued kill")
	}
	if f.calls[0]["auto"] != true {
		t.Fatal("auto mode must queue for delivery rather than await approval")
	}
}

// TestKillRecommenderNilStoreIsInert guards the wiring: a worker built without a store must be a
// no-op, not a panic in the alert path.
func TestKillRecommenderNilStoreIsInert(t *testing.T) {
	var k *KillRecommender = NewKillRecommender(nil, true)
	if ok, err := k.Evaluate(context.Background(), encryptionAlert()); ok || err != nil {
		t.Fatalf("a nil-store recommender must be inert, got ok=%v err=%v", ok, err)
	}
}
