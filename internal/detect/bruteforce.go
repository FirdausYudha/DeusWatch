// Package detect contains the DeusWatch detection engine.
//
// Phase 1 includes a built-in SSH brute-force detector as a pure component
// (no I/O) so it is easy to test. A general Sigma engine follows; this detector gives
// a quick result for the Phase 1 "definition of done" (see design doc section 6).
package detect

import (
	"sync"
	"time"

	"deuswatch/internal/ingest"
)

// BruteForceConfig configures the brute-force detection thresholds.
type BruteForceConfig struct {
	Threshold int           // number of failures within the window to fire an alert
	Window    time.Duration // observation window
	Cooldown  time.Duration // minimum interval between alerts for the same source IP
	RuleID    string
	RuleName  string
}

// DefaultBruteForceConfig: 5 failures within 1 minute, 5-minute cooldown.
func DefaultBruteForceConfig() BruteForceConfig {
	return BruteForceConfig{
		Threshold: 5,
		Window:    time.Minute,
		Cooldown:  5 * time.Minute,
		RuleID:    "deuswatch-ssh-bruteforce",
		RuleName:  "SSH Brute Force",
	}
}

// BruteForceDetector detects SSH brute force from the stream of failed auth events.
// Safe for use by many goroutines.
type BruteForceDetector struct {
	cfg       BruteForceConfig
	mu        sync.Mutex
	hits      map[string][]time.Time // source IP -> failure timestamps within the window
	lastAlert map[string]time.Time   // source IP -> last alert time (cooldown)
}

// NewBruteForceDetector creates a detector with config cfg.
func NewBruteForceDetector(cfg BruteForceConfig) *BruteForceDetector {
	return &BruteForceDetector{
		cfg:       cfg,
		hits:      make(map[string][]time.Time),
		lastAlert: make(map[string]time.Time),
	}
}

// Inspect inspects one normalized event. If this event is a failed SSH login and
// crosses the threshold, it returns an *ingest.Event alert (severity high, MITRE
// T1110, label bruteforce). Otherwise it returns nil.
func (d *BruteForceDetector) Inspect(e *ingest.Event) *ingest.Event {
	if e == nil || !isFailedSSHLogin(e) {
		return nil
	}
	ip := e.Source.IP // isFailedSSHLogin guarantees Source != nil and IP is set
	now := e.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := now.Add(-d.cfg.Window)
	kept := d.hits[ip][:0]
	for _, t := range d.hits[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	d.hits[ip] = kept

	if len(kept) < d.cfg.Threshold {
		return nil
	}
	if last, ok := d.lastAlert[ip]; ok && now.Sub(last) < d.cfg.Cooldown {
		return nil
	}
	d.lastAlert[ip] = now
	return d.buildAlert(e, len(kept), now)
}

func (d *BruteForceDetector) buildAlert(src *ingest.Event, count int, now time.Time) *ingest.Event {
	alert := &ingest.Event{
		Timestamp: now,
		Event: ingest.EventFields{
			Category: "intrusion_detection",
			Action:   "ssh_bruteforce_detected",
			Outcome:  "detected",
			Severity: ingest.SeverityHigh,
			Dataset:  "deuswatch.detect",
		},
		Source: &ingest.Endpoint{IP: src.Source.IP, Port: src.Source.Port, Geo: src.Source.Geo},
		Rule:   &ingest.Rule{ID: d.cfg.RuleID, Name: d.cfg.RuleName},
		Threat: &ingest.Threat{
			Technique:  ingest.Technique{ID: "T1110", Name: "Brute Force"},
			TacticName: "Credential Access",
		},
		DeusWatch: ingest.DeusWatch{
			Label: "bruteforce",
			// Carry over the source event's threat-intel so the alert shows it too.
			Enrichment: src.DeusWatch.Enrichment,
			Severity:   ingest.SeverityMeta{Original: ingest.SeverityHigh},
		},
	}
	if src.Host != nil {
		alert.Host = &ingest.Host{Name: src.Host.Name, OSType: src.Host.OSType, IP: src.Host.IP}
	}
	if src.User != nil {
		alert.User = &ingest.User{Name: src.User.Name, Domain: src.User.Domain}
	}
	_ = count // the occurrence count is available if we later want it in the summary
	return alert
}

// isFailedSSHLogin: a failed auth event from an IP-bearing source (sshd).
func isFailedSSHLogin(e *ingest.Event) bool {
	if e.Source == nil || e.Source.IP == "" {
		return false
	}
	if e.Event.Outcome != "failure" {
		return false
	}
	// SSH-specific: the sshd dataset, or a normalized SSH login event. Other auth sources
	// (e.g. Windows logons) are handled by their own Sigma aggregation rules.
	return e.Event.Dataset == "sshd" || e.Event.Action == "ssh_login"
}
