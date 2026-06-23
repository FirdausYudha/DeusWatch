package detect

// AGGREGATION detection runner: it runs aggregation Sigma rules (compiled to SQL by
// internal/detect/sigma) periodically against the events hypertable, then fires alerts
// for groups crossing the threshold. This is the Zircolite-style SQL path from ADR
// 0001 — generalizing the hardcoded brute-force detector to Sigma-based rules.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/ingest"
)

// DefaultAggCooldown: minimum interval between alerts for the same (rule, group), so a
// long-running attack doesn't flood alerts.
const DefaultAggCooldown = 5 * time.Minute

// AggGroup is one aggregation-query result row: group + count + last seen.
type AggGroup struct {
	Group    string
	Count    int64
	LastSeen time.Time
}

// AggExecutor runs one already-compiled aggregation query. Satisfied by *store.Store;
// stubbed in tests so the runner is tested without a DB.
type AggExecutor interface {
	QueryAgg(ctx context.Context, query string, args []any) ([]AggGroup, error)
}

// AggregateRunner runs a set of aggregation rules & tracks cooldown.
// Safe for use by many goroutines.
type AggregateRunner struct {
	rules    []*sigma.AggRule
	exec     AggExecutor
	cooldown time.Duration

	mu        sync.Mutex
	lastAlert map[string]time.Time // "ruleID\x00group" -> last alert time
}

// NewAggregateRunner creates a runner. cooldown<=0 uses DefaultAggCooldown.
func NewAggregateRunner(exec AggExecutor, rules []*sigma.AggRule, cooldown time.Duration) *AggregateRunner {
	if cooldown <= 0 {
		cooldown = DefaultAggCooldown
	}
	return &AggregateRunner{
		rules: rules, exec: exec, cooldown: cooldown,
		lastAlert: map[string]time.Time{},
	}
}

// RuleCount returns the number of loaded aggregation rules.
func (r *AggregateRunner) RuleCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.rules)
}

// SetRules atomically swaps the aggregation rules (used for live reload from the DB).
func (r *AggregateRunner) SetRules(rules []*sigma.AggRule) {
	r.mu.Lock()
	r.rules = rules
	r.mu.Unlock()
}

// RunOnce runs all rules once and returns alerts for groups that crossed the
// threshold & passed cooldown. Per-rule errors are logged by the caller; here the
// first error is returned so the next cycle still tries.
func (r *AggregateRunner) RunOnce(ctx context.Context, now time.Time) ([]*ingest.Event, error) {
	var alerts []*ingest.Event
	var firstErr error
	r.mu.Lock()
	rules := r.rules
	r.mu.Unlock()
	for _, rule := range rules {
		query, args := rule.CompileSQL()
		groups, err := r.exec.QueryAgg(ctx, query, args)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("aggregate: rule %s: %w", rule.ID, err)
			}
			continue
		}
		for _, g := range groups {
			if !r.allow(rule.ID, g.Group, now) {
				continue
			}
			alerts = append(alerts, buildAggAlert(rule, g))
		}
	}
	return alerts, firstErr
}

// DryRun runs one rule against history (over the rule's own window) without cooldown
// and without creating alerts — for testing rules on past data (design doc section 10).
func (r *AggregateRunner) DryRun(ctx context.Context, rule *sigma.AggRule) ([]AggGroup, error) {
	query, args := rule.CompileSQL()
	return r.exec.QueryAgg(ctx, query, args)
}

// allow applies the per-(rule, group) cooldown.
func (r *AggregateRunner) allow(ruleID, group string, now time.Time) bool {
	key := ruleID + "\x00" + group
	r.mu.Lock()
	defer r.mu.Unlock()
	if last, ok := r.lastAlert[key]; ok && now.Sub(last) < r.cooldown {
		return false
	}
	r.lastAlert[key] = now
	return true
}

func buildAggAlert(rule *sigma.AggRule, g AggGroup) *ingest.Event {
	tech, tactic := rule.MITRE()
	label := "sigma_agg"
	if tactic != "" {
		label = strings.ToLower(strings.ReplaceAll(tactic, " ", "_"))
	}
	ts := g.LastSeen
	if ts.IsZero() {
		ts = time.Now()
	}
	alert := &ingest.Event{
		Timestamp: ts,
		Event: ingest.EventFields{
			Category: "intrusion_detection",
			Action:   "sigma_aggregation_detected",
			Outcome:  "detected",
			Severity: rule.Severity(),
			Dataset:  "deuswatch.detect",
		},
		Rule: &ingest.Rule{ID: rule.ID, Name: rule.Title},
		Threat: &ingest.Threat{
			Technique:  ingest.Technique{ID: tech},
			TacticName: tactic,
		},
		DeusWatch: ingest.DeusWatch{
			Label:      label,
			Enrichment: ingest.Enrichment{Status: ingest.EnrichmentPending},
			Severity:   ingest.SeverityMeta{Original: rule.Severity()},
		},
	}
	// When grouping by IP, fill source.ip so enrichment & the UI work.
	if g.Group != "" {
		switch rule.GroupByField {
		case "source.ip", "src_ip", "srcip", "sourceip":
			alert.Source = &ingest.Endpoint{IP: g.Group}
		case "host.name", "hostname", "computer":
			alert.Host = &ingest.Host{Name: g.Group}
		case "user.name", "user", "username":
			alert.User = &ingest.User{Name: g.Group}
		}
	}
	return alert
}
