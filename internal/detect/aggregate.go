package detect

// Runner deteksi AGREGASI: menjalankan rule Sigma agregasi (di-compile ke SQL oleh
// internal/detect/sigma) secara periodik terhadap hypertable events, lalu memicu
// alert untuk grup yang melewati ambang. Inilah jalur SQL ala Zircolite dari ADR
// 0001 — generalisasi detektor brute-force hardcoded ke rule berbasis Sigma.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/ingest"
)

// DefaultAggCooldown: jeda minimum antar-alert untuk (rule, grup) yang sama, agar
// satu serangan berlangsung lama tidak membanjiri alert.
const DefaultAggCooldown = 5 * time.Minute

// AggGroup adalah satu baris hasil query agregasi: grup + jumlah + waktu terakhir.
type AggGroup struct {
	Group    string
	Count    int64
	LastSeen time.Time
}

// AggExecutor menjalankan satu query agregasi yang sudah di-compile. Dipenuhi oleh
// *store.Store; di-stub di test agar runner teruji tanpa DB.
type AggExecutor interface {
	QueryAgg(ctx context.Context, query string, args []any) ([]AggGroup, error)
}

// AggregateRunner menjalankan sekumpulan rule agregasi & melacak cooldown.
// Aman dipakai banyak goroutine.
type AggregateRunner struct {
	rules    []*sigma.AggRule
	exec     AggExecutor
	cooldown time.Duration

	mu        sync.Mutex
	lastAlert map[string]time.Time // "ruleID\x00grup" -> waktu alert terakhir
}

// NewAggregateRunner membuat runner. cooldown<=0 memakai DefaultAggCooldown.
func NewAggregateRunner(exec AggExecutor, rules []*sigma.AggRule, cooldown time.Duration) *AggregateRunner {
	if cooldown <= 0 {
		cooldown = DefaultAggCooldown
	}
	return &AggregateRunner{
		rules: rules, exec: exec, cooldown: cooldown,
		lastAlert: map[string]time.Time{},
	}
}

// RuleCount mengembalikan jumlah rule agregasi yang dimuat.
func (r *AggregateRunner) RuleCount() int { return len(r.rules) }

// RunOnce menjalankan semua rule sekali dan mengembalikan alert untuk grup yang
// melewati ambang & lolos cooldown. Error per-rule di-log oleh pemanggil; di sini
// error pertama dikembalikan agar siklus berikutnya tetap mencoba.
func (r *AggregateRunner) RunOnce(ctx context.Context, now time.Time) ([]*ingest.Event, error) {
	var alerts []*ingest.Event
	var firstErr error
	for _, rule := range r.rules {
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

// DryRun menjalankan satu rule terhadap histori (lewat jendela rule itu sendiri)
// tanpa cooldown dan tanpa membuat alert — untuk uji rule pada data lampau
// (design doc bagian 10).
func (r *AggregateRunner) DryRun(ctx context.Context, rule *sigma.AggRule) ([]AggGroup, error) {
	query, args := rule.CompileSQL()
	return r.exec.QueryAgg(ctx, query, args)
}

// allow menerapkan cooldown per (rule, grup).
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
	// Bila pengelompokan berdasarkan IP, isi source.ip agar enrichment & UI bekerja.
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
