package playbooks

import (
	"os"
	"path/filepath"
	"testing"

	"deuswatch/internal/ingest"
)

func TestValidate(t *testing.T) {
	ok := Spec{Label: "bruteforce", Name: "x", Steps: []string{"block the ip"}}
	if err := Validate(ok); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	bad := []Spec{
		{Label: "", Steps: []string{"a"}},              // no label
		{Label: "two words", Steps: []string{"a"}},     // label with spaces
		{Label: "x"},                                   // no steps
		{Label: "x", Steps: make([]string, 21)},        // too many steps
		{Label: "x", Steps: []string{"   "}},           // empty step
	}
	for i, sp := range bad {
		if err := Validate(sp); err == nil {
			t.Errorf("bad spec %d unexpectedly accepted", i)
		}
	}
}

func TestLiveAnnotate(t *testing.T) {
	l := NewLive()
	l.byLabel = map[string]Spec{
		"bruteforce": {Label: "bruteforce", Name: "SSH Brute Force",
			Steps: []string{"Block source.ip (progressive ban)", "Audit the targeted account"}},
	}

	// A matching alert gets the numbered playbook as its recommendation.
	ev := &ingest.Event{DeusWatch: ingest.DeusWatch{Label: "bruteforce"}}
	l.Annotate(ev)
	r := ev.DeusWatch.Remediation
	if r.Source != ingest.RemediationPlaybook || r.Status != ingest.RemediationRecommended {
		t.Fatalf("annotation must set source=playbook status=recommended, got %+v", r)
	}
	want := "1. Block source.ip (progressive ban)\n2. Audit the targeted account"
	if r.Action != want {
		t.Fatalf("action = %q, want %q", r.Action, want)
	}

	// An existing recommendation is never overwritten.
	ev2 := &ingest.Event{DeusWatch: ingest.DeusWatch{Label: "bruteforce",
		Remediation: ingest.Remediation{Action: "llm says so", Source: ingest.RemediationLLM}}}
	l.Annotate(ev2)
	if ev2.DeusWatch.Remediation.Action != "llm says so" {
		t.Fatal("annotate must not overwrite an existing recommendation")
	}

	// No label / no match / nil: no-ops that must not panic.
	l.Annotate(nil)
	l.Annotate(&ingest.Event{})
	unmatched := &ingest.Event{DeusWatch: ingest.DeusWatch{Label: "unknown_label"}}
	l.Annotate(unmatched)
	if unmatched.DeusWatch.Remediation.Action != "" {
		t.Fatal("unmatched label must stay unannotated")
	}
}

func TestReadSpecsAndNormalize(t *testing.T) {
	dir := t.TempDir()
	good := "label: Bruteforce\nname: SSH response\nsteps:\n  - 'Block the IP'\n  - 'Rotate credentials'\n"
	if err := os.WriteFile(filepath.Join(dir, "bf.yml"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.yml"), []byte("steps: {not-a-list"), 0o644); err != nil {
		t.Fatal(err)
	}
	specs := readSpecs(dir)
	if len(specs) != 1 {
		t.Fatalf("want 1 parsed spec (broken skipped), got %d", len(specs))
	}
	sp := normalize(specs[0])
	if sp.Label != "bruteforce" {
		t.Fatalf("label must be lowercased, got %q", sp.Label)
	}
	if len(sp.Steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(sp.Steps))
	}
}
