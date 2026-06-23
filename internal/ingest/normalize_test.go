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
