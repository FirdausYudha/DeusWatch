package ingest

import "testing"

func mustDecoder(t *testing.T, sp DecoderSpec) *DecoderSet {
	t.Helper()
	set, err := BuildDecoderSet([]DecoderSpec{sp})
	if err != nil {
		t.Fatalf("build decoder: %v", err)
	}
	return set
}

func TestCustomDecoderExtractsFields(t *testing.T) {
	set := mustDecoder(t, DecoderSpec{
		Name: "app", Dataset: "myapp", Category: "authentication", Outcome: "failure", Level: "medium",
		Regex: `login failed for (?P<user_name>\w+) from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})`,
	})
	SetDecoders(set)
	t.Cleanup(func() { SetDecoders(nil) })

	e, ok := Normalize(RawLog{Dataset: "myapp", Host: "h1", Message: "login failed for alice from 1.2.3.4"})
	if !ok {
		t.Fatal("a custom-decoded line should be recognized")
	}
	if e.Event.Category != "authentication" || e.Event.Outcome != "failure" || e.Event.Severity != SeverityMedium {
		t.Fatalf("static fields not applied: cat=%q out=%q sev=%v", e.Event.Category, e.Event.Outcome, e.Event.Severity)
	}
	if e.User == nil || e.User.Name != "alice" {
		t.Fatalf("user_name not extracted: %+v", e.User)
	}
	if e.Source == nil || e.Source.IP != "1.2.3.4" {
		t.Fatalf("source_ip not extracted: %+v", e.Source)
	}
	if e.Event.Original == "" {
		t.Fatal("original raw line must be preserved for keyword rules")
	}
	// A non-matching line for the same dataset falls through to unrecognized.
	if _, ok := Normalize(RawLog{Dataset: "myapp", Message: "service started"}); ok {
		t.Fatal("a line the decoder does not match must not be flagged recognized")
	}
	// A built-in dataset is unaffected by custom decoders (sshd still handled natively).
	if e, ok := Normalize(RawLog{Dataset: "sshd", Message: "Failed password for root from 9.9.9.9 port 22 ssh2"}); !ok || e.User.Name != "root" {
		t.Fatalf("built-in sshd decoding must still work: ok=%v", ok)
	}
}

func TestLoadDecoderDirExamples(t *testing.T) {
	set, err := LoadDecoderDir("../../decoders")
	if err != nil {
		t.Fatalf("load bundled decoders: %v", err)
	}
	if set.Count() < 2 {
		t.Fatalf("expected the example decoders to load, got %d", set.Count())
	}
	SetDecoders(set)
	t.Cleanup(func() { SetDecoders(nil) })

	// The vsftpd example extracts the client IP on a failed FTP login.
	e, ok := Normalize(RawLog{Dataset: "vsftpd", Message: `Mon Jul 8 10:00:00 2026 [pid 2] [alice] FAIL LOGIN: Client "1.2.3.4"`})
	if !ok || e.Source == nil || e.Source.IP != "1.2.3.4" || e.Event.Category != "authentication" {
		t.Fatalf("vsftpd example decoder did not apply: ok=%v src=%+v cat=%q", ok, e.Source, e.Event.Category)
	}
}

func TestCompileDecoderValidation(t *testing.T) {
	if err := ValidateDecoder(DecoderSpec{Regex: "x", Dataset: ""}); err == nil {
		t.Fatal("missing dataset should error")
	}
	if err := ValidateDecoder(DecoderSpec{Dataset: "d", Regex: "("}); err == nil {
		t.Fatal("an invalid regex should error")
	}
}
