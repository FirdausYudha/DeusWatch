package assistant

import (
	"strings"
	"testing"
	"unicode/utf8"
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

// The closing anchor is the last thing a small model reads before it generates, so it has to carry
// the VOICE, not the role. It used to take the persona's opening sentence, which meant Mia's anchor
// was "You are Mia, a catgirl working the quiet shift in a SOC" - a title the model had no trouble
// keeping, while the stammer and the emoji that make her recognisable were never mentioned at that
// position at all. The replies came back warm, fluent and completely generic.
func TestPersonaAnchorCarriesTheVoice(t *testing.T) {
	for _, p := range Personas() {
		a := personaAnchor(p.Text)
		if a == "" {
			t.Errorf("persona %q produces no anchor", p.ID)
			continue
		}
		if strings.HasPrefix(a, "You are") {
			t.Errorf("persona %q anchors on its role, not its voice (%q). Give it a VOICE: line.", p.ID, a)
		}
		if !utf8.ValidString(a) {
			t.Errorf("persona %q anchor is not valid UTF-8, a multi-byte rune was cut: %q", p.ID, a)
		}
		// Clipping mid-sentence drops the tail, and for a voice line the tail is usually the
		// "never do this" half. A shipped persona should declare one that fits whole.
		if strings.HasSuffix(a, "...") && !strings.Contains(p.Text, a) {
			t.Errorf("persona %q anchor was clipped: %q. Shorten its VOICE: line.", p.ID, a)
		}
	}
}

// Mia's whole point is the stammer and the emoji, so her anchor must name both or the character
// arrives as an ordinary polite assistant.
func TestMiaAnchorNamesHerTells(t *testing.T) {
	var mia string
	for _, p := range Personas() {
		if p.ID == "mia" {
			mia = personaAnchor(p.Text)
		}
	}
	if mia == "" {
		t.Fatal("no mia persona")
	}
	for _, want := range []string{"A-ah", "emoji"} {
		if !strings.Contains(mia, want) {
			t.Errorf("Mia's anchor is missing %q:\n%s", want, mia)
		}
	}
}
