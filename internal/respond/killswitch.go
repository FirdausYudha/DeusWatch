package respond

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"deuswatch/internal/ingest"
)

// Ransomware / malware kill-switch (feature 3 + docs/auto-kill.md auto mode).
//
// Two-level decision:
//   1. killWorthy classifies the alert. It returns the trigger tag and whether that trigger is
//      strong enough to be auto-approvable (community-verified YARA rule, entropy-measured
//      ransomware encryption, or a file hash flagged by many AV vendors) vs a softer signal that
//      always waits for a human.
//   2. Evaluate takes that + the KillPolicy + the guard rails (PID floor, process whitelist,
//      attribution mandatory, rate limit) and chooses recommend-only vs auto-execute.
//
// The gates only ever REDUCE what happens. Every "no" here is a "no" — there is no fall-through
// path that quietly promotes a soft signal to an auto-kill.

// KillStore is the subset of the store the recommender needs.
type KillStore interface {
	RecommendKill(ctx context.Context, agentName string, pid int, procName, exe, procStart, reason, requestedBy string, auto bool) error
}

// KillRecommender proposes process terminations for ransomware/malware-class alerts.
type KillRecommender struct {
	store KillStore
	// envAuto is the KILL_SWITCH_AUTO env override; on = "force auto regardless of DB policy".
	envAuto bool

	mu       sync.RWMutex
	policy   KillPolicy
	// recent tracks per-agent auto-kill timestamps for the sliding-window rate limiter (in-memory:
	// crossing 3/min per agent is rare, doesn't need persistence, and any pending kill is already
	// stored in agent_file_actions anyway).
	recent map[string][]time.Time
}

// NewKillRecommender builds the recommender. envAuto=true forces auto-approve on regardless of the
// DB policy — the explicit deploy-declared override, mirroring the ban engine's RESPONSE_AUTO_APPROVE.
func NewKillRecommender(st KillStore, envAuto bool) *KillRecommender {
	if st == nil {
		return nil
	}
	k := &KillRecommender{
		store:   st,
		envAuto: envAuto,
		policy:  DefaultKillPolicy(),
		recent:  map[string][]time.Time{},
	}
	if envAuto {
		k.policy.AutoApprove = true
	}
	return k
}

// SetPolicy atomically swaps the kill policy (live reload from the DB, same tick as the ban
// policy). The env override, when set, keeps auto-approve forced on.
func (k *KillRecommender) SetPolicy(p KillPolicy) {
	if k == nil {
		return
	}
	if k.envAuto {
		p.AutoApprove = true
	}
	// Ensure normalised whitelist so the O(1) membership check downstream is a plain string compare.
	p.Whitelist = normaliseWhitelist(p.Whitelist)
	k.mu.Lock()
	k.policy = p
	k.mu.Unlock()
}

// Auto reports whether the recommender is currently in auto-approve mode (honest logging/UI).
func (k *KillRecommender) Auto() bool {
	if k == nil {
		return false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.policy.AutoApprove
}

// Trigger is a stable identifier for what raised the kill recommendation — recorded in the audit
// column requested_by ("auto:yara") so an operator can filter their history by cause.
type Trigger string

const (
	TriggerRansomware  Trigger = "ransomware"  // agent-measured entropy jump on a file change
	TriggerYARA        Trigger = "yara"        // manager-side YARA match on FIM upload (docs/yara.md)
	TriggerKnownBad    Trigger = "filehash"    // file hash flagged by ≥ knownBadVendorFloor engines
	TriggerRansomRule  Trigger = "ransom_rule" // detection rule tagged as ransomware-class w/ containment
)

// knownBadVendorFloor is the minimum "N/M engines flagged" count on the file-hash detail we accept
// as "high-confidence enough to auto-kill". Below this, treat as recommend-only.
const knownBadVendorFloor = 10

// killWorthy classifies an alert. Returns the trigger, whether that trigger is *inherently*
// auto-approvable (community-verified / measured directly on the host), and a human-readable
// reason for the audit trail. worthy=false means "not kill-eligible at all".
func killWorthy(alert *ingest.Event) (worthy bool, trigger Trigger, autoApprovable bool, reason string) {
	if alert == nil {
		return false, "", false, ""
	}

	// 1. Encryption is the strong measured signal and stands on its own.
	if alert.Event.Action == "file_encrypted" {
		path := ""
		if alert.File != nil {
			path = alert.File.Path
		}
		return true, TriggerRansomware, true,
			fmt.Sprintf("encrypted %s (entropy jump measured on the host)", path)
	}

	// 2. YARA match on manager-side content scan. dw_label is set by cmd/gateway/main.go's
	// publishYARAAlert when a rule fires. The community-authored rule IS the confidence.
	if alert.DeusWatch.Label == "yara_malicious" {
		return true, TriggerYARA, true,
			"YARA rule match on file content — " + alert.DeusWatch.FileHash.Detail
	}

	// 3. File hash reputation with enough vendor consensus. The detail is "N/M engines flagged";
	// we parse the leading N and require ≥ knownBadVendorFloor. If the format doesn't match we
	// don't auto-elevate — better to recommend than to over-trust a vendor-mystery verdict.
	if alert.DeusWatch.FileHash.Verdict == "known_bad" {
		n, ok := parseLeadingInt(alert.DeusWatch.FileHash.Detail)
		if ok && n >= knownBadVendorFloor {
			return true, TriggerKnownBad, true,
				fmt.Sprintf("file hash flagged by %d vendors (%s)", n, alert.DeusWatch.FileHash.Detail)
		}
		// Below the floor: still worth acting on with human oversight.
		return true, TriggerKnownBad, false,
			"file hash flagged as known-bad by reputation feed: " + alert.DeusWatch.FileHash.Detail
	}

	// 4. Rule author explicitly authorised automated response on a ransomware-class rule (via
	// containment metadata). Author-declared = auto-approvable, same as before.
	if alert.DeusWatch.Containment != nil && alert.Rule != nil &&
		strings.Contains(strings.ToLower(alert.Rule.Name), "ransomware") {
		return true, TriggerRansomRule, true,
			"ransomware rule authorised automated response: " + alert.Rule.Name
	}

	return false, "", false, ""
}

// parseLeadingInt reads the integer prefix of s (e.g. "23/71 engines flagged" → 23, true). Empty or
// non-numeric prefix → 0, false. Used to interpret the file-hash detail string.
func parseLeadingInt(s string) (int, bool) {
	n := 0
	seen := false
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		seen = true
		n = n*10 + int(r-'0')
	}
	return n, seen
}

// Evaluate proposes a kill when the alert warrants it. Returns whether a recommendation was
// written. On auto-approvable triggers with policy.AutoApprove on, guard rails pass, and the
// rate limit not exceeded, the kill is queued for immediate delivery (auto=true); otherwise it's a
// recommendation awaiting a human. Cheap for the common case: returns immediately for non-worthy
// alerts.
func (k *KillRecommender) Evaluate(ctx context.Context, alert *ingest.Event) (bool, error) {
	if k == nil {
		return false, nil
	}
	worthy, trigger, autoApprovable, reason := killWorthy(alert)
	if !worthy {
		return false, nil
	}

	// Attribution gates — same as before, plus we make them explicit as guard rails so a future
	// change can't quietly relax them.
	if alert.Process == nil || alert.Process.PID <= 0 {
		return false, nil
	}
	if alert.Process.Start == "" && alert.Process.CommandLine == "" {
		return false, nil
	}
	if alert.Agent == nil || alert.Agent.ID == "" {
		return false, nil
	}

	// Guard rails only matter when we're actually thinking about auto-approving; if we're going
	// to recommend-only anyway the operator sees the alert and decides.
	auto := false
	requestedBy := "deuswatch-detection"
	k.mu.RLock()
	policy := k.policy
	k.mu.RUnlock()
	if policy.AutoApprove && autoApprovable {
		if block, why := blockedByGuardRails(alert.Process.PID, alert.Process.Name, policy.Whitelist); block {
			log.Printf("respond: auto-kill blocked by guard rail (%s) — falling back to recommend-only for %q pid=%d",
				why, alert.Process.Name, alert.Process.PID)
		} else if !k.allowRate(alert.Agent.ID, policy.RateLimitPerMin, time.Now()) {
			log.Printf("respond: auto-kill rate limit hit for agent %q (>%d/min) — falling back to recommend-only",
				alert.Agent.ID, policy.RateLimitPerMin)
		} else {
			auto = true
			requestedBy = "auto:" + string(trigger)
		}
	}

	if alert.Process.Name != "" {
		reason += fmt.Sprintf(" - by %s (pid %d)", alert.Process.Name, alert.Process.PID)
	}
	if alert.User != nil && alert.User.Name != "" {
		reason += " as " + alert.User.Name
	}

	if err := k.store.RecommendKill(ctx, alert.Agent.ID, alert.Process.PID,
		alert.Process.Name, alert.Process.CommandLine, alert.Process.Start,
		reason, requestedBy, auto); err != nil {
		return false, err
	}
	return true, nil
}

// blockedByGuardRails checks the two "never auto-kill" rules. Returns (true, why) if blocked.
//   - PID ≤ 100 covers kernel threads / init / systemd / early-boot daemons on every Linux distro
//     DeusWatch runs on.
//   - Case-insensitive process-name whitelist (kept sorted + lowercased by normaliseWhitelist).
func blockedByGuardRails(pid int, procName string, whitelist []string) (bool, string) {
	if pid <= 100 {
		return true, fmt.Sprintf("PID %d ≤ 100 (kernel/init/systemd range)", pid)
	}
	n := strings.ToLower(strings.TrimSpace(procName))
	if n == "" {
		return false, ""
	}
	for _, w := range whitelist {
		if w == n {
			return true, fmt.Sprintf("process %q is on the kill whitelist", procName)
		}
	}
	return false, ""
}

// allowRate is a per-agent sliding-window limiter. Returns true if a new auto-kill event RIGHT NOW
// is within the per-minute cap; on true it also records the event. Old timestamps outside the
// window get trimmed on every call so memory stays bounded per agent.
func (k *KillRecommender) allowRate(agentID string, maxPerMin int, now time.Time) bool {
	if maxPerMin <= 0 {
		return false
	}
	cutoff := now.Add(-time.Minute)
	k.mu.Lock()
	defer k.mu.Unlock()
	events := k.recent[agentID]
	// Trim events older than the window.
	kept := events[:0]
	for _, t := range events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= maxPerMin {
		k.recent[agentID] = kept
		return false
	}
	kept = append(kept, now)
	k.recent[agentID] = kept
	return true
}
