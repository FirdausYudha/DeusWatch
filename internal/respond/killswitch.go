package respond

import (
	"context"
	"fmt"
	"strings"

	"deuswatch/internal/ingest"
)

// Ransomware kill-switch recommender (feature 3).
//
// This decides whether an alert justifies PROPOSING that a process be terminated. It never kills
// anything and never reaches an endpoint on its own: it writes a recommendation that a human
// approves (or that KILL_SWITCH_AUTO promotes), and the agent then re-verifies independently and
// may still refuse. Three gates in series, each of which can only reduce what happens.
//
// The user-facing trigger conditions this implements:
//   - an unauthorized program encrypting files (entropy jump -> file_encrypted)
//   - many files changed in a short window with no clear user
//   - a file hash changed by someone who is not in a trusted session
//
// What it deliberately will NOT do is propose a kill from a file alert alone. Without an attributed
// process there is nothing safe to act on, and a recommendation an operator cannot verify is worse
// than none - it teaches people to approve things they cannot check.

// KillStore is the subset of the store the recommender needs.
type KillStore interface {
	RecommendKill(ctx context.Context, agentName string, pid int, procName, exe, procStart, reason, requestedBy string, auto bool) error
}

// KillRecommender proposes process terminations for ransomware-class alerts.
type KillRecommender struct {
	store KillStore
	auto  bool // KILL_SWITCH_AUTO: queue for immediate execution instead of awaiting approval
}

// NewKillRecommender builds the recommender. auto=true skips the human approval gate and is an
// explicit, documented opt-in; the agent's own safety checks still apply either way.
func NewKillRecommender(st KillStore, auto bool) *KillRecommender {
	if st == nil {
		return nil
	}
	return &KillRecommender{store: st, auto: auto}
}

// Auto reports whether approval is being bypassed (for honest logging/UI).
func (k *KillRecommender) Auto() bool { return k != nil && k.auto }

// killWorthy reports whether an alert is the kind of ransomware evidence that justifies proposing
// a kill, plus a human-readable reason for the audit trail.
//
// Encryption is the strong signal and stands on its own: the agent measured a real text->random
// entropy jump, which a normal deploy does not produce. Mass-change containment rules qualify only
// because the rule author explicitly authorized automated response on them.
func killWorthy(alert *ingest.Event) (bool, string) {
	if alert == nil {
		return false, ""
	}
	switch {
	case alert.Event.Action == "file_encrypted":
		path := ""
		if alert.File != nil {
			path = alert.File.Path
		}
		return true, fmt.Sprintf("encrypted %s (entropy jump measured on the host)", path)
	case alert.DeusWatch.Containment != nil && strings.Contains(strings.ToLower(alert.Rule.Name), "ransomware"):
		return true, "ransomware rule authorized automated response: " + alert.Rule.Name
	}
	return false, ""
}

// Evaluate proposes a kill when the alert warrants it. Returns whether a recommendation was
// written. Cheap for the common case: it returns immediately for alerts that are not
// ransomware-class.
func (k *KillRecommender) Evaluate(ctx context.Context, alert *ingest.Event) (bool, error) {
	if k == nil {
		return false, nil
	}
	worthy, reason := killWorthy(alert)
	if !worthy {
		return false, nil
	}
	// Gate: we must know WHICH process to act on. A file alert with no attributed process gives
	// us nothing verifiable - on Linux that means auditd who-data is not enabled, and on other
	// platforms it is simply unavailable. Refusing here is what keeps the feature honest.
	if alert.Process == nil || alert.Process.PID <= 0 {
		return false, nil
	}
	// Gate: the agent refuses a kill it cannot verify, so a proposal with no identity evidence
	// would only ever produce a refusal. Don't create it.
	if alert.Process.Start == "" && alert.Process.CommandLine == "" {
		return false, nil
	}
	if alert.Agent == nil || alert.Agent.ID == "" {
		return false, nil
	}
	if alert.Process.Name != "" {
		reason += fmt.Sprintf(" - by %s (pid %d)", alert.Process.Name, alert.Process.PID)
	}
	if alert.User != nil && alert.User.Name != "" {
		reason += " as " + alert.User.Name
	}
	err := k.store.RecommendKill(ctx, alert.Agent.ID, alert.Process.PID,
		alert.Process.Name, alert.Process.CommandLine, alert.Process.Start,
		reason, "deuswatch-detection", k.auto)
	if err != nil {
		return false, err
	}
	return true, nil
}
