// Package detect berisi engine deteksi DeusWatch.
//
// Fase 1 menyertakan detektor brute-force SSH bawaan sebagai komponen murni
// (tanpa I/O) agar mudah diuji. Engine Sigma umum menyusul; detektor ini memberi
// hasil cepat untuk "definition of done" Fase 1 (lihat design doc bagian 6).
package detect

import (
	"sync"
	"time"

	"deuswatch/internal/ingest"
)

// BruteForceConfig mengatur ambang deteksi brute force.
type BruteForceConfig struct {
	Threshold int           // jumlah kegagalan dalam window untuk memicu alert
	Window    time.Duration // jendela pengamatan
	Cooldown  time.Duration // jeda minimum antar-alert untuk source IP yang sama
	RuleID    string
	RuleName  string
}

// DefaultBruteForceConfig: 5 kegagalan dalam 1 menit, cooldown 5 menit.
func DefaultBruteForceConfig() BruteForceConfig {
	return BruteForceConfig{
		Threshold: 5,
		Window:    time.Minute,
		Cooldown:  5 * time.Minute,
		RuleID:    "deuswatch-ssh-bruteforce",
		RuleName:  "SSH Brute Force",
	}
}

// BruteForceDetector mendeteksi brute force SSH dari aliran event auth gagal.
// Aman dipakai oleh banyak goroutine.
type BruteForceDetector struct {
	cfg       BruteForceConfig
	mu        sync.Mutex
	hits      map[string][]time.Time // source IP -> timestamp kegagalan dalam window
	lastAlert map[string]time.Time   // source IP -> waktu alert terakhir (cooldown)
}

// NewBruteForceDetector membuat detektor dengan konfigurasi cfg.
func NewBruteForceDetector(cfg BruteForceConfig) *BruteForceDetector {
	return &BruteForceDetector{
		cfg:       cfg,
		hits:      make(map[string][]time.Time),
		lastAlert: make(map[string]time.Time),
	}
}

// Inspect memeriksa satu event normalized. Bila event ini kegagalan login SSH dan
// memicu ambang, mengembalikan *ingest.Event alert (severity high, MITRE T1110,
// label bruteforce). Selain itu mengembalikan nil.
func (d *BruteForceDetector) Inspect(e *ingest.Event) *ingest.Event {
	if e == nil || !isFailedSSHLogin(e) {
		return nil
	}
	ip := e.Source.IP // isFailedSSHLogin menjamin Source != nil dan IP terisi
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
		Source: &ingest.Endpoint{IP: src.Source.IP, Port: src.Source.Port},
		Rule:   &ingest.Rule{ID: d.cfg.RuleID, Name: d.cfg.RuleName},
		Threat: &ingest.Threat{
			Technique:  ingest.Technique{ID: "T1110", Name: "Brute Force"},
			TacticName: "Credential Access",
		},
		DeusWatch: ingest.DeusWatch{
			Label:      "bruteforce",
			Enrichment: ingest.Enrichment{Status: ingest.EnrichmentPending},
			Severity:   ingest.SeverityMeta{Original: ingest.SeverityHigh},
		},
	}
	if src.Host != nil {
		alert.Host = &ingest.Host{Name: src.Host.Name, OSType: src.Host.OSType, IP: src.Host.IP}
	}
	if src.User != nil {
		alert.User = &ingest.User{Name: src.User.Name, Domain: src.User.Domain}
	}
	_ = count // jumlah kejadian tersedia bila kelak ingin disertakan di ringkasan
	return alert
}

// isFailedSSHLogin: event auth gagal dari sumber ber-IP (sshd).
func isFailedSSHLogin(e *ingest.Event) bool {
	if e.Source == nil || e.Source.IP == "" {
		return false
	}
	if e.Event.Outcome != "failure" {
		return false
	}
	return e.Event.Dataset == "sshd" || e.Event.Category == "authentication"
}
