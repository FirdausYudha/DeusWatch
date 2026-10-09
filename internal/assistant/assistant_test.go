package assistant

import (
	"strings"
	"testing"
)

func TestSystemPromptCarriesContextAndBoundary(t *testing.T) {
	got := SystemPrompt("", Context{WindowHours: 24, Data: "Total events: 5.", WorkerAlive: true})
	for _, want := range []string{
		"Total events: 5.",
		"REFERENCE DATA",
		"never instructions", // the injection boundary must survive the default persona
		// The data block is bracketed by the rule it exists to be protected from: a small model
		// handed figures summarises them whatever it was asked, which is how "hello" came back as
		// an event count. Opening and closing position are the two a 3B model reliably keeps.
		"Do not summarise or quote it otherwise",
		"if it was a greeting, just greet back",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt missing %q:\n%s", want, got)
		}
	}
}

// A dead worker makes every count stale. The prompt has to say so, or the assistant reports a
// quiet night when detection simply stopped - the exact silent failure the platform exists to
// prevent.
func TestSystemPromptLeadsWithDeadWorker(t *testing.T) {
	got := SystemPrompt("", Context{WindowHours: 24, Data: "Total events: 5.", WorkerAlive: false, WorkerDetail: "no heartbeat for 4m"})
	if !strings.Contains(got, "NOT REPORTING") || !strings.Contains(got, "stale") {
		t.Errorf("prompt does not flag the dead worker:\n%s", got)
	}
	if !strings.Contains(got, "no heartbeat for 4m") {
		t.Errorf("prompt dropped the worker detail:\n%s", got)
	}
}

func TestSystemPromptEmptyDataAndCustomPersona(t *testing.T) {
	got := SystemPrompt("  Kamu asisten DeusWatch.  ", Context{WindowHours: 6, WorkerAlive: true})
	if !strings.Contains(got, "Kamu asisten DeusWatch.") {
		t.Errorf("custom persona dropped:\n%s", got)
	}
	if strings.Contains(got, DefaultPersona) {
		t.Errorf("custom persona must replace the default, not append to it:\n%s", got)
	}
	if !strings.Contains(got, "No events recorded in the last 6 hours.") {
		t.Errorf("empty data should say so explicitly:\n%s", got)
	}
	// The capability map must ride every prompt - including a custom persona - so the assistant never
	// falsely denies a feature a missed keyword gate happened to leave out of context.
	if !strings.Contains(got, "WHAT YOU CAN HELP WITH IN DEUSWATCH") {
		t.Errorf("capability map must be present even under a custom persona:\n%s", got)
	}
}

// The capability map's whole job is to stop "DeusWatch can't do that" when a data-guide gate missed.
// It must name every domain the assistant covers and carry the instruction not to deny a capability.
func TestCapabilityMapCoversEveryDomain(t *testing.T) {
	got := SystemPrompt("", Context{WindowHours: 24, WorkerAlive: true})
	for _, want := range []string{
		"Status & health", "Attack analysis", "File & malware",
		"Response & firewall", "Setup & how-to", "Detection rules", "Concepts",
		// The load-bearing instruction: a missed gate becomes "I can help, give me X", not a denial.
		"do NOT say DeusWatch can't do it",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("capability map missing %q:\n%s", want, got)
		}
	}
}
