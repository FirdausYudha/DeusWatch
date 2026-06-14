package detect

import (
	"strings"

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

// RuleCount returns the number of loaded rules.
func (d *SigmaDetector) RuleCount() int { return len(d.rules) }

// Inspect returns an alert for the FIRST matching single-event rule (nil if none).
// Multi-match support is coming later.
func (d *SigmaDetector) Inspect(e *ingest.Event) *ingest.Event {
	if e == nil || len(d.rules) == 0 {
		return nil
	}
	flat := sigma.FlattenEvent(e)
	hits := d.rules.Match(flat)
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
			Label:      label,
			Enrichment: ingest.Enrichment{Status: ingest.EnrichmentPending},
			Severity:   ingest.SeverityMeta{Original: sev},
		},
	}
	if src.Source != nil {
		alert.Source = &ingest.Endpoint{IP: src.Source.IP, Port: src.Source.Port}
	}
	if src.Host != nil {
		alert.Host = &ingest.Host{Name: src.Host.Name, OSType: src.Host.OSType, IP: src.Host.IP}
	}
	if src.User != nil {
		alert.User = &ingest.User{Name: src.User.Name, Domain: src.User.Domain}
	}
	return alert
}
