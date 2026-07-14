package ingest

import "testing"

// The exact Wazuh alert the operator pasted (SSH PAM authentication failure).
const wazuhSSHFail = `{
  "_index": "wazuh-alerts-4.x-2026.06.28",
  "_source": {
    "predecoder": {"hostname": "dev-server-firdaus", "program_name": "sshd", "timestamp": "Jun 28 17:10:06"},
    "agent": {"ip": "103.81.249.242", "name": "DEV-SERVER-DEUS", "id": "001"},
    "data": {"uid": "0", "srcip": "185.150.190.165", "euid": "0", "dstuser": "root", "tty": "ssh"},
    "manager": {"name": "wazuh.manager"},
    "rule": {
      "level": 5,
      "description": "PAM: User login failed.",
      "groups": ["pam", "syslog", "authentication_failed"],
      "firedtimes": 14,
      "mitre": {"technique": ["Password Guessing"], "id": ["T1110.001"], "tactic": ["Credential Access"]},
      "id": "5503"
    },
    "location": "journald",
    "decoder": {"name": "pam"},
    "GeoLocation": {"country_name": "United States"},
    "full_log": "Jun 28 17:10:06 dev-server-firdaus sshd[2472577]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=185.150.190.165  user=root",
    "timestamp": "2026-06-28T17:10:06.925+0000"
  }
}`

func TestNormalizeWazuhSSHFail(t *testing.T) {
	e, ok := NormalizeWazuh([]byte(wazuhSSHFail))
	if !ok {
		t.Fatal("should recognize the Wazuh alert")
	}
	// Attacker IP + geo.
	if e.Source == nil || e.Source.IP != "185.150.190.165" {
		t.Fatalf("source IP wrong: %+v", e.Source)
	}
	if e.Source.Geo == nil || e.Source.Geo.CountryISOCode != "United States" {
		t.Fatalf("geo country not mapped: %+v", e.Source.Geo)
	}
	// Targeted user + monitored host + Wazuh agent tag.
	if e.User == nil || e.User.Name != "root" {
		t.Fatalf("user wrong: %+v", e.User)
	}
	if e.Host == nil || e.Host.Name != "DEV-SERVER-DEUS" {
		t.Fatalf("host wrong: %+v", e.Host)
	}
	if e.Agent == nil || e.Agent.ID != "wazuh-agent/DEV-SERVER-DEUS" {
		t.Fatalf("agent tag wrong: %+v", e.Agent)
	}
	// Rule identity + label + MITRE + severity.
	if e.Rule == nil || e.Rule.ID != "wazuh:5503" || e.Rule.Name != "PAM: User login failed." {
		t.Fatalf("rule wrong: %+v", e.Rule)
	}
	if e.DeusWatch.Label != "credential_access" {
		t.Fatalf("label should be the MITRE tactic, got %q", e.DeusWatch.Label)
	}
	if e.Threat == nil || e.Threat.Technique.ID != "T1110.001" || e.Threat.TacticName != "Credential Access" {
		t.Fatalf("MITRE not mapped: %+v", e.Threat)
	}
	if e.Event.Severity != SeverityMedium { // Wazuh level 5 -> medium
		t.Fatalf("severity: got %v, want medium", e.Event.Severity)
	}
	if e.Event.Outcome != "failure" || e.Event.Dataset != "wazuh" {
		t.Fatalf("event fields: %+v", e.Event)
	}
	if e.Event.Original == "" {
		t.Fatal("full_log should be carried as event.original")
	}
}

func TestNormalizeWazuhBareAndReject(t *testing.T) {
	// Bare alert (no _source envelope) - what the manager's integrator actually POSTs.
	bare := `{"rule":{"level":10,"id":"5710","description":"sshd: brute force","groups":["authentication_failures"]},"data":{"srcip":"1.2.3.4"},"agent":{"name":"web1"},"full_log":"x"}`
	e, ok := NormalizeWazuh([]byte(bare))
	if !ok {
		t.Fatal("bare Wazuh alert should be recognized")
	}
	if e.Event.Severity != SeverityHigh { // level 10 -> high
		t.Fatalf("severity level 10 should be high, got %v", e.Event.Severity)
	}
	if e.DeusWatch.Label != "credential_access" { // from groups fallback (no mitre)
		t.Fatalf("label fallback wrong: %q", e.DeusWatch.Label)
	}
	// Non-Wazuh JSON must be rejected so the caller can treat it as a raw line.
	if _, ok := NormalizeWazuh([]byte(`{"foo":"bar"}`)); ok {
		t.Fatal("a non-Wazuh object must be rejected")
	}
}
