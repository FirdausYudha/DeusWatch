package ingest

import "testing"

// TestNormalizeRootcheck covers the mapping and, more importantly, the two ways it could go
// wrong: swallowing an unrelated JSON log, and being swallowed BY the FIM parser because a
// finding also carries a path.
func TestNormalizeRootcheck(t *testing.T) {
	t.Run("hidden process is critical", func(t *testing.T) {
		e := &Event{}
		msg := `{"check":"hidden_process","pid":31337,"detail":"PID 31337 is running according to the kernel but /proc does not list it"}`
		if !normalizeRootcheck(msg, e) {
			t.Fatal("a hidden-process finding did not normalize")
		}
		if e.Event.Category != "intrusion_detection" {
			t.Errorf("category = %q, want intrusion_detection", e.Event.Category)
		}
		if e.Event.Action != "rootcheck_hidden_process" {
			t.Errorf("action = %q", e.Event.Action)
		}
		if e.Event.Severity != SeverityCritical {
			t.Errorf("severity = %d, want critical: a hidden PID has no benign explanation", e.Event.Severity)
		}
		if e.DeusWatch.Label == "" {
			t.Error("no label stamped; the finding would be hidden behind the alerts-only view")
		}
		if e.Process == nil || e.Process.PID != 31337 {
			t.Errorf("process = %+v, want PID 31337", e.Process)
		}
		if e.Threat == nil || e.Threat.Technique.ID != "T1014" {
			t.Errorf("threat = %+v, want T1014 Rootkit", e.Threat)
		}
	})

	t.Run("suid in a writable dir is high, not critical", func(t *testing.T) {
		e := &Event{}
		if !normalizeRootcheck(`{"check":"suid_in_writable_dir","path":"/tmp/sh"}`, e) {
			t.Fatal("a suid finding did not normalize")
		}
		// It still has the occasional legitimate cause (a developer's test build, a vendor
		// installer), so it gets looked at rather than waking somebody.
		if e.Event.Severity != SeverityHigh {
			t.Errorf("severity = %d, want high", e.Event.Severity)
		}
		if e.File == nil || e.File.Path != "/tmp/sh" {
			t.Errorf("file = %+v, want /tmp/sh", e.File)
		}
	})

	t.Run("an unrelated JSON log is not swallowed", func(t *testing.T) {
		for _, msg := range []string{
			`{"check":"disk","status":"ok"}`,             // a health probe that happens to say "check"
			`{"path":"/etc/passwd","action":"modified"}`, // a FIM change
			`{"level":"info","msg":"started"}`,
			`not json at all`,
			`{}`,
		} {
			if normalizeRootcheck(msg, &Event{}) {
				t.Errorf("normalizeRootcheck claimed %q", msg)
			}
		}
	})

	// The ordering guard. A finding carries a "path", so a parser looking for one would read it as
	// a file change and lose the check that identifies it. Normalize must try rootcheck first.
	t.Run("a finding routed through Normalize keeps its identity", func(t *testing.T) {
		e, ok := Normalize(RawLog{
			Dataset: "rootcheck",
			Message: `{"check":"file_in_dev","path":"/dev/.hidden-config"}`,
		})
		if !ok {
			t.Fatal("Normalize rejected a rootcheck finding")
		}
		if e.Event.Action != "rootcheck_file_in_dev" {
			t.Fatalf("action = %q, want rootcheck_file_in_dev; it was parsed as something else", e.Event.Action)
		}
		if e.Event.Category == "file" {
			t.Error("the finding was categorised as a file change, which is what the ordering exists to prevent")
		}
	})
}
