package syslogin

import (
	"testing"
	"time"
)

var ref = time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)

func TestParseRFC3164(t *testing.T) {
	// A classic BSD-syslog sshd line with a PRI and a program[pid] tag.
	m, ok := Parse(`<38>Jul 18 06:44:36 fw-01 sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2`, ref)
	if !ok {
		t.Fatal("should parse")
	}
	if m.Host != "fw-01" {
		t.Fatalf("host = %q", m.Host)
	}
	if m.Tag != "sshd" { // [pid] stripped -> routes to the sshd decoder
		t.Fatalf("tag = %q, want sshd", m.Tag)
	}
	if m.Content != "Failed password for root from 1.2.3.4 port 22 ssh2" {
		t.Fatalf("content = %q", m.Content)
	}
	if m.Timestamp.Year() != 2026 || m.Timestamp.Month() != time.July || m.Timestamp.Day() != 18 {
		t.Fatalf("timestamp = %v (year should come from now)", m.Timestamp)
	}
}

func TestParseRFC3164NoPID(t *testing.T) {
	m, _ := Parse(`Jul 18 06:44:36 router1 kernel: firewall drop SRC=9.9.9.9`, ref)
	if m.Tag != "kernel" || m.Host != "router1" {
		t.Fatalf("tag/host = %q/%q", m.Tag, m.Host)
	}
	if m.Content != "firewall drop SRC=9.9.9.9" {
		t.Fatalf("content = %q", m.Content)
	}
}

func TestParseRFC5424(t *testing.T) {
	// With a structured-data element that must be skipped, not treated as the message.
	line := `<174>1 2026-07-18T06:44:36+07:00 web-01 httpd 57444 - [meta seq="1"] ModSecurity: Access denied [id "942100"]`
	m, ok := Parse(line, ref)
	if !ok {
		t.Fatal("should parse 5424")
	}
	if m.Host != "web-01" || m.Tag != "httpd" {
		t.Fatalf("host/tag = %q/%q", m.Host, m.Tag)
	}
	if m.Content != `ModSecurity: Access denied [id "942100"]` {
		t.Fatalf("content = %q (SD not skipped?)", m.Content)
	}
	if m.Timestamp.UTC().Hour() != 23 { // 06:44 +07:00 -> 23:44 UTC the previous day
		t.Fatalf("timestamp not honored: %v", m.Timestamp)
	}
}

func TestParseRFC5424NoSD(t *testing.T) {
	m, _ := Parse(`<13>1 2026-07-18T00:00:00Z host app 1 - - hello world`, ref)
	if m.Content != "hello world" || m.Tag != "app" {
		t.Fatalf("content/tag = %q/%q", m.Content, m.Tag)
	}
}

func TestParseFallbackAndEmpty(t *testing.T) {
	if _, ok := Parse("   ", ref); ok {
		t.Fatal("blank line must not parse")
	}
	// An unrecognized shape is still ingested as raw content, never dropped.
	m, ok := Parse("some non-syslog gibberish line", ref)
	if !ok || m.Content == "" {
		t.Fatalf("fallback should keep the line: %+v", m)
	}
}

func TestSplitTag(t *testing.T) {
	tag, content := splitTag("sudo[999]: pam_unix")
	if tag != "sudo" || content != "pam_unix" {
		t.Fatalf("splitTag = %q/%q", tag, content)
	}
	// A colon deep in the line (JSON, a URL) is punctuation, not a tag separator.
	tag, content = splitTag(`{"key":"value with a : colon"}`)
	if tag != "" || content == "" {
		t.Fatalf("a far colon must not be a tag: tag=%q content=%q", tag, content)
	}
}
