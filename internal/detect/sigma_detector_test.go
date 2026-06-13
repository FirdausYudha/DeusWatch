package detect

import (
	"testing"

	"deuswatch/internal/detect/sigma"
	"deuswatch/internal/ingest"
)

func TestSigmaDetectorRootLogin(t *testing.T) {
	rs, err := sigma.LoadDir("../../rules/sigma")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(rs) == 0 {
		t.Fatal("ruleset kosong — harap ada rules/sigma/*.yml")
	}
	d := NewSigmaDetector(rs)

	alert := d.Inspect(&ingest.Event{
		Event:  ingest.EventFields{Dataset: "sshd", Action: "ssh_login", Outcome: "success"},
		User:   &ingest.User{Name: "root"},
		Source: &ingest.Endpoint{IP: "203.0.113.10"},
	})
	if alert == nil {
		t.Fatal("login root sukses seharusnya memicu alert Sigma")
	}
	if alert.Rule == nil || alert.Rule.ID == "" {
		t.Fatal("alert tanpa rule id")
	}
	if alert.Threat.Technique.ID != "T1078.003" {
		t.Fatalf("MITRE salah: %q", alert.Threat.Technique.ID)
	}
	if alert.Event.Severity != ingest.SeverityMedium {
		t.Fatalf("severity salah: %v", alert.Event.Severity)
	}
	if alert.DeusWatch.Label != "persistence" {
		t.Fatalf("label salah: %q", alert.DeusWatch.Label)
	}
	if alert.Source == nil || alert.Source.IP != "203.0.113.10" {
		t.Fatalf("source IP tak terbawa: %+v", alert.Source)
	}
	t.Logf("OK: alert Sigma (rule=%s, %s, sev=%s)", alert.Rule.ID, alert.Threat.Technique.ID, alert.Event.Severity)

	// user lain tidak memicu rule khusus root
	if d.Inspect(&ingest.Event{
		Event: ingest.EventFields{Dataset: "sshd", Action: "ssh_login", Outcome: "success"},
		User:  &ingest.User{Name: "deploy"},
	}) != nil {
		t.Fatal("login non-root tidak boleh memicu rule root-login")
	}
}
