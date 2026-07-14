// Package selfhealth implements DeusWatch's self-monitoring (design doc section 13):
// agent liveness states and the internal `selfhealth` alerts that flow through the
// SAME pipeline as attack alerts - a security system that stops silently is more
// dangerous than no system at all, and a dead agent can mean an attacker killed it.
package selfhealth

import (
	"fmt"
	"time"

	"deuswatch/internal/ingest"
)

// Agent liveness states, maintained by the worker's health checker.
const (
	StatusUnknown      = "unknown"      // enrolled, never seen
	StatusOnline       = "online"       // heartbeat fresh, agent reports healthy
	StatusDegraded     = "degraded"     // heartbeat fresh but the agent reports a problem (e.g. buffer piling up)
	StatusDisconnected = "disconnected" // heartbeats missed - raises a HIGH selfhealth alert
	StatusStale        = "stale"        // offline for a long time (already alerted at disconnect)
)

// Defaults: agents heartbeat every 30s; 3 missed + tolerance = disconnected.
const (
	DefaultDisconnectedAfter = 2 * time.Minute
	DefaultStaleAfter        = 24 * time.Hour
)

// AgentHealth is one agent's stored health snapshot (from the agents table).
type AgentHealth struct {
	ID       string
	Name     string
	OS       string
	LastSeen *time.Time
	Status   string // current stored status
	Degraded bool   // agent's self-reported flag from the heartbeat
	Detail   string // agent's self-reported detail, e.g. "217 buffered batch(es)"
}

// Compute returns the status the agent should have at `now`.
func Compute(a AgentHealth, now time.Time, disconnectedAfter, staleAfter time.Duration) string {
	if a.LastSeen == nil {
		return StatusUnknown
	}
	since := now.Sub(*a.LastSeen)
	switch {
	case since > staleAfter:
		return StatusStale
	case since > disconnectedAfter:
		return StatusDisconnected
	case a.Degraded:
		return StatusDegraded
	default:
		return StatusOnline
	}
}

// Transition is a status change plus the selfhealth event to store/notify for it
// (nil Event when the change is silent, e.g. disconnected -> stale).
type Transition struct {
	From, To string
	Event    *ingest.Event
}

// Evaluate computes the agent's status; when it changed it returns the transition
// with the event to emit. Returns nil when nothing changed.
func Evaluate(a AgentHealth, now time.Time, disconnectedAfter, staleAfter time.Duration) *Transition {
	next := Compute(a, now, disconnectedAfter, staleAfter)
	if next == a.Status {
		return nil
	}
	tr := &Transition{From: a.Status, To: next}
	switch next {
	case StatusDisconnected:
		// The one that matters: alert loudly. A dead agent is either broken - or silenced.
		since := time.Duration(0)
		if a.LastSeen != nil {
			since = now.Sub(*a.LastSeen).Round(time.Second)
		}
		tr.Event = agentEvent(a, now, ingest.SeverityHigh, "agent_disconnected",
			fmt.Sprintf("Agent %q (%s) stopped reporting: no heartbeat for %s. A dead agent can mean a crash - or an attacker disabling it to erase their tracks.",
				a.Name, orDash(a.OS), since))
		tr.Event.Threat = &ingest.Threat{
			Technique:  ingest.Technique{ID: "T1562.001", Name: "Impair Defenses: Disable or Modify Tools"},
			TacticName: "Defense Evasion",
		}
	case StatusDegraded:
		tr.Event = agentEvent(a, now, ingest.SeverityMedium, "agent_degraded",
			fmt.Sprintf("Agent %q (%s) is degraded: %s. The heartbeat still arrives but logs are not getting through.",
				a.Name, orDash(a.OS), orDash(a.Detail)))
	case StatusOnline:
		// Recovery is informational: stored for the timeline, silent on channels
		// (below the default notification threshold).
		if a.Status == StatusDisconnected || a.Status == StatusStale || a.Status == StatusDegraded {
			tr.Event = agentEvent(a, now, ingest.SeverityInfo, "agent_recovered",
				fmt.Sprintf("Agent %q (%s) is reporting again (was %s).", a.Name, orDash(a.OS), a.Status))
		}
	}
	return tr
}

// agentEvent builds a selfhealth event bound to the agent, shaped like every other
// alert so the dashboard, notifications and audit trail treat it uniformly.
func agentEvent(a AgentHealth, now time.Time, sev ingest.Severity, action, msg string) *ingest.Event {
	return &ingest.Event{
		Timestamp: now,
		Event: ingest.EventFields{
			Category: "selfhealth",
			Action:   action,
			Outcome:  "detected",
			Severity: sev,
			Dataset:  "deuswatch.selfhealth",
			Original: msg,
		},
		// agent.id on the dashboard is the agent NAME (cert CN) everywhere else, so use
		// a.Name here too - not the internal DB UUID - for a consistent, readable Agent column.
		Host:  &ingest.Host{Name: a.Name, OSType: a.OS},
		Agent: &ingest.Agent{ID: a.Name},
		Rule:  &ingest.Rule{ID: "deuswatch_agent_health", Name: "Agent Health Monitor"},
		DeusWatch: ingest.DeusWatch{
			Label:    "selfhealth",
			Severity: ingest.SeverityMeta{Original: sev},
		},
	}
}

// JanitorEvent is the HIGH selfhealth alert emitted every time the disk-watermark
// janitor drops chunks early - the admin must grow the disk or tighten retention.
func JanitorEvent(now time.Time, dropped int, before time.Time, usedPercent int, budget string) *ingest.Event {
	return &ingest.Event{
		Timestamp: now,
		Event: ingest.EventFields{
			Category: "selfhealth",
			Action:   "janitor_dropped_chunks",
			Outcome:  "success",
			Severity: ingest.SeverityHigh,
			Dataset:  "deuswatch.selfhealth",
			Original: fmt.Sprintf("Storage janitor dropped %d oldest event chunk(s) (data before %s) because the log DB crossed %d%% of the %s budget. Grow STORAGE_BUDGET_GB / the disk, or tighten retention.",
				dropped, before.UTC().Format("2006-01-02 15:04 MST"), usedPercent, budget),
		},
		Rule: &ingest.Rule{ID: "deuswatch_disk_janitor", Name: "Disk Watermark Janitor"},
		DeusWatch: ingest.DeusWatch{
			Label:    "selfhealth",
			Severity: ingest.SeverityMeta{Original: ingest.SeverityHigh},
		},
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
