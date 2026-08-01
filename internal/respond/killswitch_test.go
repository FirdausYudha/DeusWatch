package respond

import (
	"context"
	"testing"
	"time"

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

// enableAuto returns a recommender with auto-approve on and a permissive policy — the
// baseline configuration that the guard-rail tests below build on top of.
func enableAuto(t *testing.T, f *fakeKillStore) *KillRecommender {
	t.Helper()
	k := NewKillRecommender(f, false)
	p := DefaultKillPolicy()
	p.AutoApprove = true
	k.SetPolicy(p)
	return k
}

// yaraAlert is the manager-side YARA content-scan alert shape (cmd/gateway/main.go publishes this).
func yaraAlert() *ingest.Event {
	e := encryptionAlert()
	e.Event.Action = "yara_match"
	e.DeusWatch.Label = "yara_malicious"
	e.DeusWatch.FileHash.Verdict = "yara_malicious"
	e.DeusWatch.FileHash.Detail = "matched: DeusWatch_Suspicious_PHP_Webshell"
	return e
}

// TestAutoApproveOnYARAMatch: a YARA match on an attributed process with auto-approve on and no
// guard rail blocking must produce auto=true.
func TestAutoApproveOnYARAMatch(t *testing.T) {
	f := &fakeKillStore{}
	k := enableAuto(t, f)
	ok, err := k.Evaluate(context.Background(), yaraAlert())
	if err != nil || !ok || len(f.calls) != 1 {
		t.Fatalf("expected one kill call, got ok=%v err=%v calls=%v", ok, err, f.calls)
	}
	if f.calls[0]["auto"] != true {
		t.Fatal("YARA match with auto-approve on must be queued (auto=true)")
	}
	if got := f.calls[0]["reason"]; got == "" {
		t.Fatal("reason must be populated for the audit trail")
	}
}

// TestAutoApproveOnRansomware: entropy-measured file_encrypted with attribution + auto-approve on
// → auto=true. This was already the strong signal in the pre-contract killWorthy.
func TestAutoApproveOnRansomware(t *testing.T) {
	f := &fakeKillStore{}
	k := enableAuto(t, f)
	if _, err := k.Evaluate(context.Background(), encryptionAlert()); err != nil {
		t.Fatal(err)
	}
	if f.calls[0]["auto"] != true {
		t.Fatal("ransomware with auto-approve on must be queued")
	}
}

// TestAutoApproveOnKnownBadHash: a file-hash verdict flagged by ≥ knownBadVendorFloor engines is
// treated as high-confidence and auto-approvable. Below the floor it stays recommend-only.
func TestAutoApproveOnKnownBadHash(t *testing.T) {
	mk := func(detail string) *ingest.Event {
		e := encryptionAlert()
		e.Event.Action = "file_created"
		e.DeusWatch.FileHash.Verdict = "known_bad"
		e.DeusWatch.FileHash.Detail = detail
		return e
	}
	f := &fakeKillStore{}
	k := enableAuto(t, f)
	// Above the floor.
	if _, err := k.Evaluate(context.Background(), mk("23/71 engines flagged")); err != nil {
		t.Fatal(err)
	}
	if f.calls[0]["auto"] != true {
		t.Fatalf("hash with 23 vendors ≥ %d floor must be auto", knownBadVendorFloor)
	}
	// Reset store; below the floor must stay recommend-only.
	f2 := &fakeKillStore{}
	k2 := enableAuto(t, f2)
	if _, err := k2.Evaluate(context.Background(), mk("3/71 engines flagged")); err != nil {
		t.Fatal(err)
	}
	if f2.calls[0]["auto"] != false {
		t.Fatalf("hash with 3 vendors < %d floor must stay recommend-only", knownBadVendorFloor)
	}
}

// TestAutoApproveOffWithoutAttribution: a YARA match with no process start-time (agent didn't
// attribute) must never auto-kill, even in auto mode.
func TestAutoApproveOffWithoutAttribution(t *testing.T) {
	f := &fakeKillStore{}
	k := enableAuto(t, f)
	alert := yaraAlert()
	alert.Process.Start, alert.Process.CommandLine = "", "" // strip both identity tokens
	ok, err := k.Evaluate(context.Background(), alert)
	if err != nil {
		t.Fatal(err)
	}
	if ok || len(f.calls) != 0 {
		t.Fatalf("no attribution → no kill even in auto; got ok=%v calls=%v", ok, f.calls)
	}
}

// TestWhitelistBlocksAutoKill: a YARA match against sshd must degrade to recommend-only regardless
// of auto mode, so a bad rule can never take an ops-critical process down.
func TestWhitelistBlocksAutoKill(t *testing.T) {
	f := &fakeKillStore{}
	k := enableAuto(t, f)
	alert := yaraAlert()
	alert.Process.Name = "sshd"
	if _, err := k.Evaluate(context.Background(), alert); err != nil {
		t.Fatal(err)
	}
	if f.calls[0]["auto"] != false {
		t.Fatal("sshd in the default whitelist must not be auto-killed")
	}
}

// TestPIDUnder100NeverAutoKilled: PID 42 is systemd/init territory on every distro DeusWatch
// runs on — the numeric guard rail is stricter than the whitelist alone.
func TestPIDUnder100NeverAutoKilled(t *testing.T) {
	f := &fakeKillStore{}
	k := enableAuto(t, f)
	alert := yaraAlert()
	alert.Process.PID, alert.Process.Name = 42, "some-daemon"
	if _, err := k.Evaluate(context.Background(), alert); err != nil {
		t.Fatal(err)
	}
	if f.calls[0]["auto"] != false {
		t.Fatal("PID ≤ 100 must never be auto-killed")
	}
}

// TestRateLimitDegradesToRecommend: after 3 auto-kills within one minute on the same agent, the
// 4th falls back to recommend-only. The alert itself is still stored — dropping it would hide the
// burst from the operator.
func TestRateLimitDegradesToRecommend(t *testing.T) {
	f := &fakeKillStore{}
	k := enableAuto(t, f) // default rate limit = 3
	for i := 0; i < 4; i++ {
		alert := yaraAlert()
		alert.Process.PID = 5000 + i // distinct PIDs so each is a fresh event
		if _, err := k.Evaluate(context.Background(), alert); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.calls) != 4 {
		t.Fatalf("all four alerts must be stored, got %d", len(f.calls))
	}
	for i := 0; i < 3; i++ {
		if f.calls[i]["auto"] != true {
			t.Fatalf("first 3 within the window must be auto, got call %d auto=%v", i, f.calls[i]["auto"])
		}
	}
	if f.calls[3]["auto"] != false {
		t.Fatal("4th within the window must degrade to recommend-only")
	}
}

// TestPolicyDefaultsFailClosed: a fresh recommender (no SetPolicy call, no env override) must
// leave every kill as a recommendation even on a rock-solid YARA match.
func TestPolicyDefaultsFailClosed(t *testing.T) {
	f := &fakeKillStore{}
	k := NewKillRecommender(f, false) // no env, no SetPolicy → default policy
	if _, err := k.Evaluate(context.Background(), yaraAlert()); err != nil {
		t.Fatal(err)
	}
	if f.calls[0]["auto"] != false {
		t.Fatal("default policy must be recommend-only until an admin opts in")
	}
}

// TestAllowRateSlidesWindow: after events age out of the 1-minute window, the limiter frees up
// again. This is what "sliding" means and what protects the limiter from getting stuck on stale
// timestamps after a burst.
func TestAllowRateSlidesWindow(t *testing.T) {
	k := NewKillRecommender(&fakeKillStore{}, false)
	base := time.Now()
	// Fill the window.
	for i := 0; i < 3; i++ {
		if !k.allowRate("web01", 3, base) {
			t.Fatalf("call %d in an empty window must be allowed", i)
		}
	}
	if k.allowRate("web01", 3, base) {
		t.Fatal("4th within the same second must be blocked")
	}
	// 61 seconds later, everything ages out.
	if !k.allowRate("web01", 3, base.Add(61*time.Second)) {
		t.Fatal("after the window fully slides, a new event must be allowed")
	}
}
