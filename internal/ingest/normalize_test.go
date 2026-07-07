package ingest

import (
	"fmt"
	"testing"
)

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

// A descriptively-named source ("fim (download)", "firewall (ufw)", "nginx prod") must still
// route to the right parser - the label is free-form in the UI, so matching must be on the
// base keyword, not the exact string.
func TestNormalizeDescriptiveDatasetNames(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "fim (download)", Host: "dev", Message: `{"path":"/home/deus/Download/test.txt","action":"created","sha256":"x"}`})
	if !ok || e.Event.Category != "file" || e.Event.Action != "file_created" {
		t.Fatalf("fim (download) should normalize as a file event: ok=%v cat=%q act=%q", ok, e.Event.Category, e.Event.Action)
	}
	if e.Event.Dataset != "fim (download)" {
		t.Fatalf("original dataset label must be preserved, got %q", e.Event.Dataset)
	}
	fw, ok := Normalize(RawLog{Dataset: "firewall (ufw)", Host: "edge", Message: "[UFW BLOCK] SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=40000 DPT=23"})
	if !ok || fw.Event.Category != "network" || fw.Source == nil || fw.Source.IP != "1.2.3.4" {
		t.Fatalf("firewall (ufw) should normalize as a network event with the source IP: ok=%v cat=%q", ok, fw.Event.Category)
	}
	if _, ok := Normalize(RawLog{Dataset: "windows-security", Message: `{"id":4625,"user":"admin"}`}); !ok {
		t.Fatal("windows-* datasets must still route to the windows parser")
	}
}

func TestNormalizeSuricataAlert(t *testing.T) {
	line := `{"event_type":"alert","src_ip":"1.2.3.4","src_port":40000,"dest_ip":"10.0.0.5","dest_port":443,"proto":"TCP","app_proto":"tls","alert":{"action":"allowed","signature_id":2020123,"signature":"ET MALWARE Win32/Trojan CnC Checkin","category":"A Network Trojan was detected","severity":1,"metadata":{"mitre_technique_id":["T1071"],"mitre_tactic_name":["command_and_control"]}}}`
	e, ok := Normalize(RawLog{Dataset: "suricata", Host: "ids01", AgentID: "sensor", Message: line})
	if !ok {
		t.Fatal("a Suricata alert should be recognized")
	}
	if e.Event.Category != "intrusion_detection" || e.Event.Severity != SeverityHigh {
		t.Fatalf("bad mapping: cat=%q sev=%v", e.Event.Category, e.Event.Severity)
	}
	if e.Source == nil || e.Source.IP != "1.2.3.4" || e.Source.Port != 40000 {
		t.Fatalf("bad source: %+v", e.Source)
	}
	if e.Destination == nil || e.Destination.IP != "10.0.0.5" {
		t.Fatalf("bad dest: %+v", e.Destination)
	}
	if e.Rule == nil || e.Rule.ID != "suricata-2020123" || e.Rule.Name == "" {
		t.Fatalf("bad rule: %+v", e.Rule)
	}
	if e.Threat == nil || e.Threat.Technique.ID != "T1071" {
		t.Fatalf("bad threat: %+v", e.Threat)
	}
	if e.DeusWatch.Label == "" {
		t.Fatal("a Suricata alert must be pre-labeled so it surfaces as an alert and drives response")
	}
	// A descriptive dataset name still routes, and a non-alert EVE line is ignored.
	if _, ok := Normalize(RawLog{Dataset: "suricata (eve)", Message: line}); !ok {
		t.Fatal("descriptive 'suricata (eve)' dataset must still route")
	}
	if _, ok := Normalize(RawLog{Dataset: "suricata", Message: `{"event_type":"flow","src_ip":"1.2.3.4"}`}); ok {
		t.Fatal("a non-alert EVE record (flow) must not be flagged as an alert")
	}
}

func TestNormalizeFIMBadPayload(t *testing.T) {
	if _, ok := Normalize(RawLog{Dataset: "fim", Message: "not json"}); ok {
		t.Fatal("a broken FIM payload must not be flagged as recognized")
	}
}

// An sshd line we don't structure into user/outcome still gets category=authentication, so
// category-scoped auth rules can match its raw text (e.g. break-in / scanning signatures).
func TestNormalizeWindowsExtendedIDs(t *testing.T) {
	cases := []struct {
		id       int
		category string
		action   string
	}{
		{4688, "process", "windows_process_created"},
		{4104, "process", "powershell_scriptblock"},
		{4720, "iam", "windows_account_created"},
		{4732, "iam", "windows_group_member_added"},
		{1102, "iam", "windows_audit_log_cleared"},
	}
	for _, c := range cases {
		msg := fmt.Sprintf(`{"id":%d,"text":"rendered event text"}`, c.id)
		e, ok := Normalize(RawLog{Dataset: "windows-security", Host: "win01", Message: msg})
		if !ok {
			t.Fatalf("event %d should be recognized", c.id)
		}
		if e.Event.Category != c.category || e.Event.Action != c.action {
			t.Fatalf("event %d: got cat=%q act=%q want %q/%q", c.id, e.Event.Category, e.Event.Action, c.category, c.action)
		}
		if e.Host == nil || e.Host.OSType != "windows" {
			t.Fatalf("event %d should carry host.os.type=windows", c.id)
		}
	}
}

func TestNormalizeSSHDUnstructuredGetsAuthCategory(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "sshd", Message: "reverse mapping ... POSSIBLE BREAK-IN ATTEMPT!"})
	if ok {
		t.Fatal("this line is not a structured Failed/Accepted event")
	}
	if e.Event.Category != "authentication" {
		t.Fatalf("any sshd line should carry category=authentication, got %q", e.Event.Category)
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

// Web access log lines -> web event with the client IP + full line kept in event.original,
// so the keyword-based web-defacement / judi-online rules can match against it.
func TestNormalizeWeb(t *testing.T) {
	line := `154.127.69.8 - - [10/Oct/2026:13:55:36 +0000] "GET /slot-3-kingdoms/ HTTP/1.1" 200 5120 "-" "Mozilla/5.0"`
	e, ok := Normalize(RawLog{Dataset: "web", Host: "web01", Message: line})
	if !ok {
		t.Fatal("a web access line should be recognized")
	}
	if e.Event.Category != "web" || e.Event.Action != "http_request" {
		t.Fatalf("wrong event: %+v", e.Event)
	}
	if e.Source == nil || e.Source.IP != "154.127.69.8" {
		t.Fatalf("client IP not extracted: %+v", e.Source)
	}
	if e.Event.Original != line {
		t.Fatalf("original line not kept (needed for keyword rules): %q", e.Event.Original)
	}
	// loopback must not become a bannable source
	e2, _ := Normalize(RawLog{Dataset: "nginx", Message: `127.0.0.1 - - [..] "GET / HTTP/1.1" 200 1`})
	if e2.Source != nil {
		t.Fatalf("loopback should be ignored as a source: %+v", e2.Source)
	}
}
