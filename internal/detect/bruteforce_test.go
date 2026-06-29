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
			t.Fatalf("failure #%d should not trigger an alert yet", i+1)
		}
	}
	alert := d.Inspect(failedLogin("203.0.113.10", "root", base.Add(5*time.Second)))
	if alert == nil {
		t.Fatal("failure #5 should trigger an alert")
	}
	if alert.DeusWatch.Label != "bruteforce" {
		t.Fatalf("wrong label: %q", alert.DeusWatch.Label)
	}
	if alert.Threat.Technique.ID != "T1110" {
		t.Fatalf("wrong MITRE technique: %q", alert.Threat.Technique.ID)
	}
	if alert.Event.Severity != ingest.SeverityHigh {
		t.Fatalf("wrong severity: %v", alert.Event.Severity)
	}
	if alert.Source.IP != "203.0.113.10" {
		t.Fatalf("wrong source IP: %q", alert.Source.IP)
	}
	t.Logf("OK: alert triggered (label=%s, %s/%s, severity=%s)",
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
		t.Fatalf("should be exactly 1 alert due to cooldown, got %d", alerts)
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
			t.Fatal("a successful login must not trigger an alert")
		}
	}
	// Different IPs are counted independently: 4 from one IP do not trigger (default threshold 5).
	base := time.Now()
	for i := 0; i < 4; i++ {
		if d.Inspect(failedLogin("192.0.2.7", "root", base.Add(time.Duration(i)*time.Second))) != nil {
			t.Fatal("4 failures (< threshold 5) must not trigger")
		}
	}
}

// Windows logon failures must NOT trigger the SSH brute-force detector (they have their own
// Sigma aggregation rule). Guards the dataset/action scoping in isFailedSSHLogin.
func TestBruteForceIgnoresWindowsLogons(t *testing.T) {
	cfg := BruteForceConfig{Threshold: 5, Window: time.Minute, Cooldown: 5 * time.Minute, RuleID: "deuswatch-ssh-bruteforce", RuleName: "SSH Brute Force"}
	d := NewBruteForceDetector(cfg)
	base := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		ev := &ingest.Event{
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Event:     ingest.EventFields{Category: "authentication", Action: "windows_logon", Outcome: "failure", Dataset: "windows-security"},
			Source:    &ingest.Endpoint{IP: "203.0.113.77"},
			User:      &ingest.User{Name: "administrator"},
		}
		if a := d.Inspect(ev); a != nil {
			t.Fatalf("windows logon #%d must not trigger the SSH brute-force detector", i+1)
		}
	}
}
