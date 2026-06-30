// Package respond is the DeusWatch response engine (Phase 2): it turns alerts into
// block recommendations and applies them via a firewall backend (nftables/Mikrotik/
// CrowdSec) behind the Responder interface, with an approval workflow & progressive ban.
//
// Flow: alert (source IP) -> Engine.Recommend -> a 'recommended' row in
// response_actions. An analyst/admin approves -> Engine.Execute -> Responder.Block ->
// 'executed'. The ban duration grows with the IP's history (BanPolicy).
package respond

import (
	"context"
	"time"
)

// Status is an action's lifecycle status (mirrors deuswatch.remediation.status).
type Status string

const (
	StatusRecommended Status = "recommended"
	StatusApproved    Status = "approved"
	StatusExecuted    Status = "executed"
	StatusDismissed   Status = "dismissed"
	StatusFailed      Status = "failed"
	StatusUnbanned    Status = "unbanned" // a previously-executed block that was lifted
)

// Action is one response recommendation/action.
type Action struct {
	ID           string     `json:"id"`
	CreatedAt    time.Time  `json:"created_at"`
	SourceIP     string     `json:"source_ip"`
	ActionType   string     `json:"action"` // "block"
	Reason       string     `json:"reason"`
	RuleID       string     `json:"rule_id"`
	BanSeconds   int        `json:"ban_seconds"` // 0 = permanent
	OffenseCount int        `json:"offense_count"`
	Source       string     `json:"source"` // playbook | llm
	Status       Status     `json:"status"`
	Responder    string     `json:"responder"`
	DecidedBy    string     `json:"decided_by"`
	DecidedAt    *time.Time `json:"decided_at"`
	ExecutedAt   *time.Time `json:"executed_at"`
	Error        string     `json:"error"`
}

// BanDuration returns the ban duration as a time.Duration (0 = permanent).
func (a Action) BanDuration() time.Duration { return time.Duration(a.BanSeconds) * time.Second }

// Responder applies a block action to a firewall/IPS backend.
// d == 0 means a permanent block.
type Responder interface {
	Name() string
	Block(ctx context.Context, ip string, d time.Duration) error
	Unblock(ctx context.Context, ip string) error
}

// BanPolicy determines the progressive ban duration based on the offense count.
type BanPolicy struct {
	Durations   []time.Duration // durations for the 1st, 2nd, ... offense (escalation ladder)
	Permanent   bool            // true: an offense beyond the list -> permanent (0)
	Window      time.Duration   // only count prior offenses within this window (0 = all history)
	AutoApprove bool            // true: execute the ban automatically, no manual approval
}

// DefaultBanPolicy: 10m, 1h, 24h, then permanent.
func DefaultBanPolicy() BanPolicy {
	return BanPolicy{
		Durations: []time.Duration{10 * time.Minute, time.Hour, 24 * time.Hour},
		Permanent: true,
	}
}

// Duration returns the ban duration for the offense-th offense (1-based).
// 0 means permanent.
func (p BanPolicy) Duration(offense int) time.Duration {
	if len(p.Durations) == 0 {
		return 0
	}
	if offense < 1 {
		offense = 1
	}
	if offense <= len(p.Durations) {
		return p.Durations[offense-1]
	}
	if p.Permanent {
		return 0 // permanent
	}
	return p.Durations[len(p.Durations)-1] // cap at the longest duration
}
