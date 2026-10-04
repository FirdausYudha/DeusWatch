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
}
