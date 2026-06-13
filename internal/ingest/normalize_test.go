package ingest

import "testing"

func TestNormalizeSSHDFailed(t *testing.T) {
	e, ok := Normalize(RawLog{
		Dataset: "sshd", Host: "web01", AgentID: "agent-1",
		Message: "Failed password for root from 203.0.113.10 port 54321 ssh2",
	})
	if !ok {
		t.Fatal("baris failed password seharusnya dikenali")
	}
	if e.Event.Category != "authentication" || e.Event.Outcome != "failure" {
		t.Fatalf("event salah: %+v", e.Event)
	}
	if e.Event.Severity != SeverityLow {
		t.Fatalf("severity=%v, mau low", e.Event.Severity)
	}
	if e.Source == nil || e.Source.IP != "203.0.113.10" || e.Source.Port != 54321 {
		t.Fatalf("source salah: %+v", e.Source)
	}
	if e.User == nil || e.User.Name != "root" {
		t.Fatalf("user salah: %+v", e.User)
	}
}

func TestNormalizeSSHDInvalidUser(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "sshd", Message: "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"})
	if !ok || e.User.Name != "admin" || e.Source.IP != "1.2.3.4" {
		t.Fatalf("parse invalid user gagal: ok=%v %+v", ok, e)
	}
}

func TestNormalizeSSHDAccepted(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "sshd", Message: "Accepted password for deploy from 10.0.0.5 port 22 ssh2"})
	if !ok || e.Event.Outcome != "success" || e.User.Name != "deploy" {
		t.Fatalf("parse accepted gagal: ok=%v %+v", ok, e)
	}
}

func TestNormalizeUnknownKeepsOriginal(t *testing.T) {
	e, ok := Normalize(RawLog{Dataset: "sshd", Message: "Server listening on 0.0.0.0 port 22."})
	if ok {
		t.Fatal("baris non-auth tidak boleh ditandai dikenali")
	}
	if e.Event.Original == "" || e.Event.Dataset != "sshd" {
		t.Fatalf("event minimal seharusnya tetap menyimpan original & dataset: %+v", e.Event)
	}
}
