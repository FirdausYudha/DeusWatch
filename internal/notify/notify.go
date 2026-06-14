// Package notify sends alert notifications to external channels (Telegram, email,
// webhook) with a severity threshold + dedup/throttle (design doc Phase 2).
//
// The Dispatcher filters out alerts below the threshold, suppresses duplicates within
// the throttle window (per rule+IP), then fans them out to all configured sinks.
package notify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"deuswatch/internal/ingest"
)

// Notification is the alert summary ready to send to a channel.
type Notification struct {
	Title     string
	Severity  ingest.Severity
	SourceIP  string
	Rule      string
	Technique string
	Tactic    string
	Label     string
	Time      time.Time
}

// FromEvent builds a Notification from a DCS alert event.
func FromEvent(ev *ingest.Event) Notification {
	n := Notification{
		Severity: ev.Event.Severity,
		Label:    ev.DeusWatch.Label,
		Time:     ev.Timestamp,
	}
	if ev.Source != nil {
		n.SourceIP = ev.Source.IP
	}
	if ev.Rule != nil {
		n.Rule = ev.Rule.Name
		if n.Rule == "" {
			n.Rule = ev.Rule.ID
		}
	}
	if ev.Threat != nil {
		n.Technique = ev.Threat.Technique.ID
		n.Tactic = ev.Threat.TacticName
	}
	n.Title = n.Rule
	if n.Title == "" {
		n.Title = "DeusWatch alert"
	}
	return n
}

// dedupKey: a notification is considered a duplicate if rule + source IP match within the window.
func (n Notification) dedupKey() string { return n.Rule + "|" + n.SourceIP }

// Text returns the plain-text message body (used by Telegram/email/log).
func (n Notification) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "🚨 [%s] %s\n", strings.ToUpper(n.Severity.String()), n.Title)
	if n.SourceIP != "" {
		fmt.Fprintf(&b, "Source IP: %s\n", n.SourceIP)
	}
	if n.Technique != "" {
		fmt.Fprintf(&b, "MITRE: %s %s\n", n.Technique, n.Tactic)
	}
	if !n.Time.IsZero() {
		fmt.Fprintf(&b, "Time: %s\n", n.Time.UTC().Format(time.RFC3339))
	}
	return strings.TrimRight(b.String(), "\n")
}

// Notifier sends one notification to a channel.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, n Notification) error
}

// Dispatcher filters + throttles + fans out notifications to many sinks.
type Dispatcher struct {
	sinks       []Notifier
	minSeverity ingest.Severity
	throttle    time.Duration

	mu       sync.Mutex
	lastSent map[string]time.Time
	now      func() time.Time
}

// NewDispatcher creates a dispatcher. throttle<=0 disables dedup.
func NewDispatcher(minSeverity ingest.Severity, throttle time.Duration, sinks ...Notifier) *Dispatcher {
	return &Dispatcher{
		sinks: sinks, minSeverity: minSeverity, throttle: throttle,
		lastSent: map[string]time.Time{}, now: time.Now,
	}
}

// Enabled reports whether any sink is configured.
func (d *Dispatcher) Enabled() bool { return d != nil && len(d.sinks) > 0 }

// SinkNames returns the names of the active sinks.
func (d *Dispatcher) SinkNames() []string {
	names := make([]string, 0, len(d.sinks))
	for _, s := range d.sinks {
		names = append(names, s.Name())
	}
	return names
}

// Dispatch filters (severity + throttle) then sends to all sinks. Each sink's error
// is collected; one sink failing does not stop the others. Returns nil when
// suppressed by the threshold/throttle.
func (d *Dispatcher) Dispatch(ctx context.Context, n Notification) error {
	if !d.Enabled() {
		return nil
	}
	if n.Severity < d.minSeverity {
		return nil
	}
	if !d.allow(n.dedupKey()) {
		return nil
	}
	var errs []string
	for _, s := range d.sinks {
		if err := s.Notify(ctx, n); err != nil {
			errs = append(errs, s.Name()+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("notify: %s", strings.Join(errs, "; "))
	}
	return nil
}

// allow applies the per-key throttle/dedup.
func (d *Dispatcher) allow(key string) bool {
	if d.throttle <= 0 {
		return true
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.lastSent[key]; ok && now.Sub(last) < d.throttle {
		return false
	}
	d.lastSent[key] = now
	return true
}
