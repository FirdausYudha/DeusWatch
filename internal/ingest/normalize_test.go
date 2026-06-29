package ingest

import "testing"

func TestNormalizeSSHDFailed(t *testing.T) {
	e, ok := Normalize(RawLog{
		Dataset: "sshd", Host: "web01", AgentID: "agent-1",
		Message: "Failed password for root from 203.0.113.10 port 54321 ssh2",
	})
	if !ok {
		t.Fatal("a failed-password line should be recognized")
	}
	if e.Event.Category != "authentication" || e.Event.Outcome != "failure" {
		t.Fatalf("wrong event: %+v", e.Event)
	}
	if e.Event.Severity != SeverityLow {
		t.Fatalf("severity=%v, want low", e.Event.Severity)
	}
	if e.Source == nil || e.Source.IP != "203.0.113.10" || e.Source.Port != 54321 {
		t.Fatalf("wrong source: %+v", e.Source)
	}
	if e.User == nil || e.User.Name != "root" {
		t.Fatalf("wrong user: %+v", e.User)
	}
}

// Real auth.log lines carry a syslog prefix (timestamp, host, "sshd[pid]:") — the
// source IP must still be extracted from anywhere in the line.
func TestNormalizeSSHDWithSyslogPrefix(t *testing.T) {
	for _, msg := range []string{
		"2026-06-23T11:49:41.123456+07:00 deus-vm sshd[1234]: Failed password for invalid user baduser from 192.168.81.135 port 54321 ssh2",
		"Jun 23 11:49:41 deus-vm sshd[1234]: Failed password for root from 192.168.81.135 port 22 ssh2",
	} {
		e, ok := Normalize(RawLog{Dataset: "sshd", Message: msg})
		if !ok {
			t.Fatalf("prefixed line not recognized: %q", msg)
		}
		if e.Event.Outcome != "failure" || e.Source == nil || e.Source.IP != "192.168.81.135" {
			t.Fatalf("source IP not extracted from %q: %+v", msg, e.Source)
		}
	}
}

func TestNormalizeSSHDInvalidUser(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "sshd", Message: "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"})
	if !ok || e.User.Name != "admin" || e.Source.IP != "1.2.3.4" {
		t.Fatalf("invalid-user parse failed: ok=%v %+v", ok, e)
	}
}

func TestNormalizeSSHDAccepted(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "sshd", Message: "Accepted password for deploy from 10.0.0.5 port 22 ssh2"})
	if !ok || e.Event.Outcome != "success" || e.User.Name != "deploy" {
		t.Fatalf("accepted parse failed: ok=%v %+v", ok, e)
	}
}

func TestNormalizeFIM(t *testing.T) {
	e, ok := Normalize(RawLog{
		Dataset: "fim", Host: "web01",
		Message: `{"path":"/etc/passwd","action":"modified","sha256":"abc123","mode":"-rw-r--r--"}`,
	})
	if !ok {
		t.Fatal("FIM payload should be recognized")
	}
	if e.Event.Category != "file" || e.Event.Action != "file_modified" {
		t.Fatalf("wrong FIM event: %+v", e.Event)
	}
	if e.Event.Severity != SeverityMedium {
		t.Fatalf("modified severity should be medium, got %v", e.Event.Severity)
	}
	if e.File == nil || e.File.Path != "/etc/passwd" || e.File.HashSHA256 != "abc123" {
		t.Fatalf("wrong file fields: %+v", e.File)
	}
}

func TestNormalizeFIMCreatedLowSeverity(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "fim", Message: `{"path":"/tmp/new","action":"created","sha256":"x"}`})
	if !ok || e.Event.Severity != SeverityLow {
		t.Fatalf("created should be low: ok=%v sev=%v", ok, e.Event.Severity)
	}
}

func TestNormalizeFIMBadPayload(t *testing.T) {
	if _, ok := Normalize(RawLog{Dataset: "fim", Message: "not json"}); ok {
		t.Fatal("a broken FIM payload must not be flagged as recognized")
	}
}

func TestNormalizeUnknownKeepsOriginal(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "sshd", Message: "Server listening on 0.0.0.0 port 22."})
	if ok {
		t.Fatal("a non-auth line must not be flagged as recognized")
	}
	if e.Event.Original == "" || e.Event.Dataset != "sshd" {
		t.Fatalf("the minimal event should still keep original & dataset: %+v", e.Event)
	}
}

// Windows Security 4625 (failed logon): mapped by EventID, IP/user extracted, OS=windows.
func TestNormalizeWindowsFailedLogon(t *testing.T) {
	e, ok := Normalize(RawLog{
		Dataset: "windows-security", Host: "win-dc-01",
		Message: `{"id":4625,"ip":"198.51.100.23","user":"administrator","logon_type":"10","text":"An account failed to log on."}`,
	})
	if !ok {
		t.Fatal("4625 should be recognized")
	}
	if e.Event.Category != "authentication" || e.Event.Action != "windows_logon" || e.Event.Outcome != "failure" {
		t.Fatalf("wrong event: %+v", e.Event)
	}
	if e.Event.Severity != SeverityLow {
		t.Fatalf("severity=%v, want low", e.Event.Severity)
	}
	if e.Source == nil || e.Source.IP != "198.51.100.23" {
		t.Fatalf("source IP not extracted: %+v", e.Source)
	}
	if e.User == nil || e.User.Name != "administrator" {
		t.Fatalf("user not extracted: %+v", e.User)
	}
	if e.Host == nil || e.Host.OSType != "windows" {
		t.Fatalf("OSType should be windows: %+v", e.Host)
	}
	if e.Event.Original != "An account failed to log on." {
		t.Fatalf("original should be the rendered text, got %q", e.Event.Original)
	}
}

func TestNormalizeWindowsSuccessAndLockout(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "windows-security",
		Message: `{"id":4624,"ip":"10.0.0.5","user":"svc-sql","text":"An account was successfully logged on."}`})
	if !ok || e.Event.Outcome != "success" || e.Event.Severity != SeverityInfo {
		t.Fatalf("4624 success mapping wrong: ok=%v %+v", ok, e.Event)
	}
	e2, ok2 := Normalize(RawLog{Dataset: "windows-security",
		Message: `{"id":4740,"user":"admin","text":"A user account was locked out."}`})
	if !ok2 || e2.Event.Action != "account_locked" || e2.Event.Severity != SeverityMedium {
		t.Fatalf("4740 lockout mapping wrong: ok=%v %+v", ok2, e2.Event)
	}
}

// An unmapped Windows event (or a loopback IP) is still stored but not flagged as a known type.
func TestNormalizeWindowsUnmappedAndLoopback(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "windows-system",
		Message: `{"id":7036,"text":"The Print Spooler service entered the running state."}`})
	if ok {
		t.Fatal("an unmapped event should return ok=false")
	}
	if e.Event.Original != "The Print Spooler service entered the running state." {
		t.Fatalf("text should still be unwrapped, got %q", e.Event.Original)
	}
	// loopback source must not become a source IP
	e2, _ := Normalize(RawLog{Dataset: "windows-security",
		Message: `{"id":4625,"ip":"127.0.0.1","user":"x","text":"local"}`})
	if e2.Source != nil {
		t.Fatalf("loopback should be ignored as a source: %+v", e2.Source)
	}
}

// Firewall (UFW/Netfilter) drop lines -> network event with source IP + dest port, used by
// the Port Scan aggregation rule.
func TestNormalizeFirewallBlock(t *testing.T) {
	msg := "Jun 29 17:05:01 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb SRC=203.0.113.77 DST=10.0.0.5 LEN=40 PROTO=TCP SPT=40000 DPT=23 WINDOW=1024"
	e, ok := Normalize(RawLog{Dataset: "firewall", Host: "edge", Message: msg})
	if !ok {
		t.Fatal("a UFW BLOCK line should be recognized")
	}
	if e.Event.Category != "network" || e.Event.Action != "firewall_block" || e.Event.Outcome != "blocked" {
		t.Fatalf("wrong event: %+v", e.Event)
	}
	if e.Source == nil || e.Source.IP != "203.0.113.77" {
		t.Fatalf("source IP not parsed: %+v", e.Source)
	}
	if e.Destination == nil || e.Destination.Port != 23 {
		t.Fatalf("dest port not parsed: %+v", e.Destination)
	}
	if e.Network == nil || e.Network.Transport != "tcp" {
		t.Fatalf("transport not parsed: %+v", e.Network)
	}
}

func TestNormalizeFirewallAllowAndNonMatch(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "firewall",
		Message: "kernel: [UFW ALLOW] IN=eth0 SRC=10.0.0.9 DST=10.0.0.5 PROTO=UDP DPT=53"})
	if !ok || e.Event.Action != "firewall_allow" {
		t.Fatalf("allow line mapping wrong: ok=%v %+v", ok, e.Event)
	}
	if _, ok := Normalize(RawLog{Dataset: "firewall", Message: "kernel: random line without fields"}); ok {
		t.Fatal("a line without SRC= must not be treated as a firewall event")
	}
}
