package detect

import (
	"testing"
	"time"

	"deuswatch/internal/ingest"
)

func failedLogin(ip, user string, ts time.Time) *ingest.Event {
	return &ingest.Event{
		Timestamp: ts,
		Event: ingest.EventFields{
			Category: "authentication", Action: "ssh_login",
			Outcome: "failure", Dataset: "sshd", Severity: ingest.SeverityMedium,
		},
		Source: &ingest.Endpoint{IP: ip, Port: 54321},
		User:   &ingest.User{Name: user},
		Host:   &ingest.Host{Name: "web01", OSType: "linux"},
	}
}

func TestBruteForceThreshold(t *testing.T) {
	cfg := BruteForceConfig{Threshold: 5, Window: time.Minute, Cooldown: 5 * time.Minute, RuleID: "deuswatch-ssh-bruteforce", RuleName: "SSH Brute Force"}
	d := NewBruteForceDetector(cfg)
	base := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 4; i++ {
		if a := d.Inspect(failedLogin("203.0.113.10", "root", base.Add(time.Duration(i)*time.Second))); a != nil {
			t.Fatalf("kegagalan ke-%d seharusnya belum memicu alert", i+1)
		}
	}
	alert := d.Inspect(failedLogin("203.0.113.10", "root", base.Add(5*time.Second)))
	if alert == nil {
		t.Fatal("kegagalan ke-5 seharusnya memicu alert")
	}
	if alert.DeusWatch.Label != "bruteforce" {
		t.Fatalf("label salah: %q", alert.DeusWatch.Label)
	}
	if alert.Threat.Technique.ID != "T1110" {
		t.Fatalf("MITRE technique salah: %q", alert.Threat.Technique.ID)
	}
	if alert.Event.Severity != ingest.SeverityHigh {
		t.Fatalf("severity salah: %v", alert.Event.Severity)
	}
	if alert.Source.IP != "203.0.113.10" {
		t.Fatalf("source IP salah: %q", alert.Source.IP)
	}
	t.Logf("OK: alert terpicu (label=%s, %s/%s, severity=%s)",
		alert.DeusWatch.Label, alert.Threat.Technique.ID, alert.Threat.TacticName, alert.Event.Severity)
}

func TestBruteForceCooldown(t *testing.T) {
	cfg := BruteForceConfig{Threshold: 3, Window: time.Minute, Cooldown: 10 * time.Minute}
	d := NewBruteForceDetector(cfg)
	base := time.Now()
	alerts := 0
	for i := 0; i < 6; i++ {
		if d.Inspect(failedLogin("198.51.100.5", "admin", base.Add(time.Duration(i)*time.Second))) != nil {
			alerts++
		}
	}
	if alerts != 1 {
		t.Fatalf("harusnya tepat 1 alert karena cooldown, dapat %d", alerts)
	}
}

func TestIgnoresSuccessAndOtherIPs(t *testing.T) {
	d := NewBruteForceDetector(DefaultBruteForceConfig())
	success := &ingest.Event{
		Timestamp: time.Now(),
		Event:     ingest.EventFields{Category: "authentication", Outcome: "success", Dataset: "sshd"},
		Source:    &ingest.Endpoint{IP: "203.0.113.10"},
	}
	for i := 0; i < 20; i++ {
		if d.Inspect(success) != nil {
			t.Fatal("login sukses tidak boleh memicu alert")
		}
	}
	// IP berbeda dihitung independen: 4 dari satu IP tak memicu (threshold default 5).
	base := time.Now()
	for i := 0; i < 4; i++ {
		if d.Inspect(failedLogin("192.0.2.7", "root", base.Add(time.Duration(i)*time.Second))) != nil {
			t.Fatal("4 kegagalan (< threshold 5) tidak boleh memicu")
		}
	}
}
