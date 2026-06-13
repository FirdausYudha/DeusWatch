// Package notify mengirim notifikasi alert ke saluran eksternal (Telegram, email,
// webhook) dengan ambang severity + dedup/throttle (design doc Fase 2).
//
// Dispatcher menyaring alert di bawah ambang, menekan duplikat dalam jendela
// throttle (per rule+IP), lalu menyebarkannya ke semua sink yang dikonfigurasi.
package notify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"deuswatch/internal/ingest"
)

// Notification adalah ringkasan alert yang siap dikirim ke saluran.
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

// FromEvent membangun Notification dari event alert DCS.
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

// dedupKey: notifikasi dianggap duplikat bila rule + source IP sama dalam window.
func (n Notification) dedupKey() string { return n.Rule + "|" + n.SourceIP }

// Text mengembalikan badan pesan teks polos (dipakai Telegram/email/log).
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
		fmt.Fprintf(&b, "Waktu: %s\n", n.Time.UTC().Format(time.RFC3339))
	}
	return strings.TrimRight(b.String(), "\n")
}

// Notifier mengirim satu notifikasi ke sebuah saluran.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, n Notification) error
}

// Dispatcher menyaring + men-throttle + menyebarkan notifikasi ke banyak sink.
type Dispatcher struct {
	sinks       []Notifier
	minSeverity ingest.Severity
	throttle    time.Duration

	mu       sync.Mutex
	lastSent map[string]time.Time
	now      func() time.Time
}

// NewDispatcher membuat dispatcher. throttle<=0 menonaktifkan dedup.
func NewDispatcher(minSeverity ingest.Severity, throttle time.Duration, sinks ...Notifier) *Dispatcher {
	return &Dispatcher{
		sinks: sinks, minSeverity: minSeverity, throttle: throttle,
		lastSent: map[string]time.Time{}, now: time.Now,
	}
}

// Enabled melaporkan apakah ada sink terkonfigurasi.
func (d *Dispatcher) Enabled() bool { return d != nil && len(d.sinks) > 0 }

// SinkNames mengembalikan nama sink yang aktif.
func (d *Dispatcher) SinkNames() []string {
	names := make([]string, 0, len(d.sinks))
	for _, s := range d.sinks {
		names = append(names, s.Name())
	}
	return names
}

// Dispatch menyaring (severity + throttle) lalu mengirim ke semua sink. Error tiap
// sink dikumpulkan; satu sink gagal tak menghentikan yang lain. Mengembalikan nil
// bila ditekan ambang/throttle.
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

// allow menerapkan throttle/dedup per key.
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
