package store

import (
	"context"
	"testing"
	"time"
)

// TestKillSwitchQueue exercises the whole manager-side lifecycle against real Postgres:
// recommend -> (dedupe) -> approve -> deliver to the agent -> record the outcome. The properties
// asserted here are the ones that keep a destructive action safe.
func TestKillSwitchQueue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	const agent = "killtest01"
	cleanup := func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM agent_file_actions WHERE agent_name=$1`, agent)
	}
	cleanup()
	defer cleanup()

	// A detection proposes a kill. It must land INERT, awaiting a human.
	if err := st.RecommendKill(ctx, agent, 4242, "cryptor", "/tmp/.x/cryptor", "88123",
		"encrypted /srv/data/report.docx", "deuswatch-detection", false); err != nil {
		t.Fatalf("recommend: %v", err)
	}
	reqs, err := st.ListKillRequests(ctx, true, 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var got *KillRequest
	for i := range reqs {
		if reqs[i].AgentName == agent {
			got = &reqs[i]
		}
	}
	if got == nil {
		t.Fatalf("the recommendation should be listed as pending, got %+v", reqs)
	}
	if got.Status != "recommended" {
		t.Fatalf("a proposed kill must await approval, got status %q", got.Status)
	}
	if got.Reason == "" {
		t.Fatal("a pending recommendation must carry WHY, so an operator can judge it")
	}

	// THE KEY SAFETY PROPERTY: an unapproved recommendation must never be delivered to an agent.
	pend, err := st.PendingFileActions(ctx, agent)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	for _, a := range pend {
		if a.Action == "kill_process" {
			t.Fatalf("an UNAPPROVED kill was delivered to the agent: %+v", a)
		}
	}

	// Re-proposing the same process must not pile up duplicate recommendations.
	if err := st.RecommendKill(ctx, agent, 4242, "cryptor", "/tmp/.x/cryptor", "88123",
		"encrypted another file", "deuswatch-detection", false); err != nil {
		t.Fatalf("re-recommend: %v", err)
	}
	reqs, _ = st.ListKillRequests(ctx, true, 50)
	n := 0
	for _, r := range reqs {
		if r.AgentName == agent {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the same process must not queue twice, got %d pending", n)
	}

	// A request with nothing to verify against is refused outright - the agent would only refuse
	// it anyway, and an un-approvable button is worse than no button.
	if err := st.RecommendKill(ctx, agent, 777, "ghost", "", "", "no identity", "x", false); err == nil {
		t.Fatal("a kill request with no identity evidence must be rejected")
	}

	// Approve: only now may it reach the agent, carrying the identity for re-verification.
	if err := st.ApproveKill(ctx, got.ID, "analyst1"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	pend, err = st.PendingFileActions(ctx, agent)
	if err != nil {
		t.Fatalf("pending after approve: %v", err)
	}
	var deliv *FileAction
	for i := range pend {
		if pend[i].Action == "kill_process" {
			deliv = &pend[i]
		}
	}
	if deliv == nil {
		t.Fatalf("an approved kill must be delivered, got %+v", pend)
	}
	// If any of these are dropped in transit the agent refuses the kill, so assert them explicitly.
	if deliv.PID != 4242 || deliv.ProcStart != "88123" || deliv.ProcName != "cryptor" {
		t.Fatalf("process identity must survive delivery, got pid=%d start=%q name=%q",
			deliv.PID, deliv.ProcStart, deliv.ProcName)
	}
	if deliv.Path != "/tmp/.x/cryptor" {
		t.Fatalf("executable path must survive delivery, got %q", deliv.Path)
	}

	// Approving twice must not re-fire a kill (double-click / stale tab).
	if err := st.ApproveKill(ctx, got.ID, "analyst1"); err == nil {
		t.Fatal("re-approving an already-approved kill must fail")
	}

	// The agent reports a REFUSAL. It is a completed decision, and the honest outcome must be
	// preserved verbatim rather than being flattened into a success.
	const outcome = "skipped_protected: protected system process sshd"
	if err := st.SetFileActionResult(ctx, deliv.ID, "done", outcome); err != nil {
		t.Fatalf("set result: %v", err)
	}
	all, err := st.ListKillRequests(ctx, false, 50)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	for _, r := range all {
		if r.ID != deliv.ID {
			continue
		}
		if r.Result != outcome {
			t.Fatalf("the agent's outcome must be reported verbatim, got %q", r.Result)
		}
		if r.Reason != "" {
			t.Fatal("a decided request must show the outcome, not the detection reason")
		}
	}
}

// TestKillSwitchDismiss proves a rejected recommendation is recorded (not deleted) and can never
// later be approved.
func TestKillSwitchDismiss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := Connect(ctx, dsn())
	if err != nil {
		t.Skipf("Postgres unavailable — skipping: %v", err)
	}
	defer st.Close()

	const agent = "killtest02"
	cleanup := func() { _, _ = st.pool.Exec(ctx, `DELETE FROM agent_file_actions WHERE agent_name=$1`, agent) }
	cleanup()
	defer cleanup()

	if err := st.RecommendKill(ctx, agent, 9001, "backup", "/usr/bin/backup", "5150", "looked encrypted", "det", false); err != nil {
		t.Fatalf("recommend: %v", err)
	}
	reqs, _ := st.ListKillRequests(ctx, true, 50)
	var id int64
	for _, r := range reqs {
		if r.AgentName == agent {
			id = r.ID
		}
	}
	if id == 0 {
		t.Fatal("recommendation not found")
	}

	if err := st.DismissKill(ctx, id, "analyst1"); err != nil {
		t.Fatalf("dismiss: %v", err)
	}
	// A dismissed recommendation must never become executable.
	if err := st.ApproveKill(ctx, id, "analyst1"); err == nil {
		t.Fatal("a dismissed recommendation must not be approvable afterwards")
	}
	pend, _ := st.PendingFileActions(ctx, agent)
	for _, a := range pend {
		if a.Action == "kill_process" {
			t.Fatal("a dismissed kill must never reach the agent")
		}
	}
	// It is recorded, with who decided - an audit trail, not a deletion.
	all, _ := st.ListKillRequests(ctx, false, 50)
	found := false
	for _, r := range all {
		if r.ID == id {
			found = true
			if r.Result == "" {
				t.Fatal("a dismissal must be recorded with its reason")
			}
		}
	}
	if !found {
		t.Fatal("a dismissed recommendation must remain in the audit trail")
	}
}
