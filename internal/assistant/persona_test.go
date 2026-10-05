package assistant

import (
	"strings"
	"testing"
)

// The UI offers "Load the default to edit" and its editor truncates at store.MaxPersonaLen. If the
// built-in default ever outgrows that cap, loading it silently cuts the tail off, and the tail is
// where the prompt-injection boundary lives. The constant is duplicated rather than imported to
// keep this package free of a store dependency; the comment on store.MaxPersonaLen points back.
const maxPersonaLen = 10000

func TestDefaultPersonaFitsTheEditor(t *testing.T) {
	if n := len(DefaultPersona); n >= maxPersonaLen {
		t.Fatalf("DefaultPersona is %d chars, at or over the %d cap: loading it into the editor "+
			"would truncate it. Raise store.MaxPersonaLen (and this constant) first.", n, maxPersonaLen)
	}
}

// Small models keep the first and last instructions and lose the middle. These two must stay at the
// ends, because the failure they prevent is the one actually observed: asked "hello", the model
// recited the event counts it had been handed.
func TestDefaultPersonaLeadsWithAnswerOnlyWhatWasAsked(t *testing.T) {
	head := DefaultPersona
	if i := strings.Index(head, "HOW YOU TALK"); i > 0 {
		head = head[:i]
	}
	for _, want := range []string{"Answer the message you were actually sent", "greet them back in one line"} {
		if !strings.Contains(head, want) {
			t.Errorf("the opening block must contain %q, or a 3B model will not see it:\n%s", want, head)
		}
	}
}
