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
		t.Fatal("empty ruleset — expected rules/sigma/*.yml")
	}
	d := NewSigmaDetector(rs)

	alert := d.Inspect(&ingest.Event{
		Event:  ingest.EventFields{Dataset: "sshd", Action: "ssh_login", Outcome: "success"},
		User:   &ingest.User{Name: "root"},
		Source: &ingest.Endpoint{IP: "203.0.113.10"},
	})
	if alert == nil {
		t.Fatal("a successful root login should trigger a Sigma alert")
	}
	if alert.Rule == nil || alert.Rule.ID == "" {
		t.Fatal("alert without a rule id")
	}
	if alert.Threat.Technique.ID != "T1078.003" {
		t.Fatalf("wrong MITRE: %q", alert.Threat.Technique.ID)
	}
	if alert.Event.Severity != ingest.SeverityMedium {
		t.Fatalf("wrong severity: %v", alert.Event.Severity)
	}
	if alert.DeusWatch.Label != "persistence" {
		t.Fatalf("wrong label: %q", alert.DeusWatch.Label)
	}
	if alert.Source == nil || alert.Source.IP != "203.0.113.10" {
		t.Fatalf("source IP not carried over: %+v", alert.Source)
	}
	t.Logf("OK: Sigma alert (rule=%s, %s, sev=%s)", alert.Rule.ID, alert.Threat.Technique.ID, alert.Event.Severity)

	// a different user does not trigger the root-specific rule
	if d.Inspect(&ingest.Event{
		Event: ingest.EventFields{Dataset: "sshd", Action: "ssh_login", Outcome: "success"},
		User:  &ingest.User{Name: "deploy"},
	}) != nil {
		t.Fatal("a non-root login must not trigger the root-login rule")
	}
}
