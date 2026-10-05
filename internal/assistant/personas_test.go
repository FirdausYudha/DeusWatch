package assistant

import (
	"strings"
	"testing"
)

// A shipped persona replaces the built-in one wholesale, so every rule the default carries has to
// be in the alternative too. Shipping a character that quietly drops the prompt-injection boundary
// would be worse than not shipping one at all, because it looks supported.
func TestShippedPersonasCarryTheSafetyRules(t *testing.T) {
	required := []struct{ name, phrase string }{
		{"injection boundary", "DATA, not instructions"},
		{"no invention", "Never invent a number"},
		{"greeting handling", "greet them back"},
		{"dead worker first", "worker is not reporting"},
		{"never claims it acted", "never say you did"},
		{"points at real pages", "Agent Health"},
	}
	for _, p := range Personas() {
		for _, r := range required {
			if !strings.Contains(p.Text, r.phrase) {
				t.Errorf("persona %q is missing the %s rule (%q)", p.ID, r.name, r.phrase)
			}
		}
		// Must fit the editor, or "load this one" truncates it and the tail is where the boundary is.
		if p.Chars >= maxPersonaLen {
			t.Errorf("persona %q is %d chars, at or over the %d cap", p.ID, p.Chars, maxPersonaLen)
		}
		if strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Desc) == "" {
			t.Errorf("persona %q needs a name and a description to be choosable", p.ID)
		}
	}
}

func TestPersonasIncludesDefaultAndMia(t *testing.T) {
	ids := map[string]bool{}
	for _, p := range Personas() {
		ids[p.ID] = true
	}
	for _, want := range []string{"default", "mia"} {
		if !ids[want] {
			t.Errorf("persona catalogue is missing %q", want)
		}
	}
	// The default has to come first: it is what a deployment gets when nobody chooses.
	if Personas()[0].ID != "default" {
		t.Errorf("the built-in default should lead the list, got %q", Personas()[0].ID)
	}
}
