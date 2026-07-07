package detect

import (
	"strings"
	"sync"

	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/ingest"
)

// Detector is one detection unit: it inspects a single event and returns an alert
// when it fires (nil otherwise). BruteForceDetector & SigmaDetector satisfy it.
type Detector interface {
	Inspect(e *ingest.Event) *ingest.Event
}

// SigmaDetector evaluates events against a Sigma Ruleset (single-event rules).
// The interim engine uses the internal/detect/sigma prototype behind this interface;
// it can be swapped for a mature Go fork later without changing the worker (see ADR 0001).
type SigmaDetector struct {
	mu    sync.RWMutex
	rules sigma.Ruleset
}

// NewSigmaDetector wraps a Ruleset.
func NewSigmaDetector(rs sigma.Ruleset) *SigmaDetector {
	return &SigmaDetector{rules: rs}
}

// LoadSigmaDir loads rules from dir and returns a detector.
func LoadSigmaDir(dir string) (*SigmaDetector, error) {
	rs, err := sigma.LoadDir(dir)
	if err != nil {
		return nil, err
	}
	return &SigmaDetector{rules: rs}, nil
}

// SetRules atomically swaps the rule set (used for live reload from the DB).
func (d *SigmaDetector) SetRules(rs sigma.Ruleset) {
	d.mu.Lock()
	d.rules = rs
	d.mu.Unlock()
}

// RuleCount returns the number of loaded rules.
func (d *SigmaDetector) RuleCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.rules)
}

// Inspect returns an alert for the FIRST matching single-event rule (nil if none).
// Multi-match support is coming later.
func (d *SigmaDetector) Inspect(e *ingest.Event) *ingest.Event {
	d.mu.RLock()
	rules := d.rules
	d.mu.RUnlock()
	if e == nil || len(rules) == 0 {
		return nil
	}
	hits := rules.Match(sigma.FlattenEvent(e))
	if len(hits) == 0 {
		return nil
	}
	return buildSigmaAlert(hits[0], e)
}

func buildSigmaAlert(r *sigma.Rule, src *ingest.Event) *ingest.Event {
	tech, tactic := r.MITRE()
	sev := r.Severity()
	label := "sigma_match"
	if tactic != "" {
		label = strings.ToLower(strings.ReplaceAll(tactic, " ", "_"))
	}

	alert := &ingest.Event{
		Timestamp: src.Timestamp,
		Event: ingest.EventFields{
			Category: "intrusion_detection",
			Action:   "sigma_match",
			Outcome:  "detected",
			Severity: sev,
			Dataset:  "deuswatch.detect",
		},
		Rule: &ingest.Rule{ID: r.ID, Name: r.Title},
		Threat: &ingest.Threat{
			Technique:  ingest.Technique{ID: tech},
			TacticName: tactic,
		},
		DeusWatch: ingest.DeusWatch{
			Label: label,
			// Carry over the threat-intel already computed on the source event so the
			// labeled alert shows it too (otherwise the "Alerts only" view loses it).
			Enrichment: src.DeusWatch.Enrichment,
			Severity:   ingest.SeverityMeta{Original: sev},
		},
	}
	if src.Source != nil {
		alert.Source = &ingest.Endpoint{IP: src.Source.IP, Port: src.Source.Port, Geo: src.Source.Geo}
	}
	if src.Host != nil {
		alert.Host = &ingest.Host{Name: src.Host.Name, OSType: src.Host.OSType, IP: src.Host.IP}
	}
	// Carry the agent identity over — the response engine needs it to isolate the host.
	if src.Agent != nil {
		alert.Agent = &ingest.Agent{ID: src.Agent.ID, Version: src.Agent.Version}
	}
	if src.User != nil {
		alert.User = &ingest.User{Name: src.User.Name, Domain: src.User.Domain}
	}
	// Carry the file identity over so FIM / file-based rule alerts show WHICH file changed
	// (the raw FIM event carries it, but the labeled alert is a separate event that would
	// otherwise have no path/location).
	if src.File != nil {
		alert.File = &ingest.File{
			Path: src.File.Path, HashSHA256: src.File.HashSHA256,
			Owner: src.File.Owner, Mode: src.File.Mode,
		}
	}
	// A rule with a mitigation_action block authorizes automated containment. Carry the
	// directive onto the alert so the response engine can act without re-parsing the rule.
	if m := r.Mitigation; m != nil && m.ActionType == "network_containment" {
		alert.DeusWatch.Containment = &ingest.Containment{
			ActionType:     m.ActionType,
			TimeoutSeconds: m.TimeoutSeconds,
			// Default to High so an unspecified threshold still needs a serious alert to auto-isolate.
			Threshold: ingest.ParseSeverity(m.CriticalityThreshold, ingest.SeverityHigh),
		}
	}
	return alert
}
