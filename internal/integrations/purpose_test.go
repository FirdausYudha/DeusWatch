package integrations

import "testing"

func TestLLMPurposeMatches(t *testing.T) {
	cases := []struct {
		configured, want string
		ok               bool
	}{
		// Existing behaviour, unchanged: blank and "both" serve triage and report.
		{"", "triage", true},
		{"", "report", true},
		{"both", "triage", true},
		{"both", "report", true},
		{"triage", "triage", true},
		{"triage", "report", false},
		{"report", "triage", false},
		{" Report ", "report", true}, // stored values are not guaranteed trimmed or lowercased

		// The assistant is opt-in. An upgrade must not hand a chat panel to a deployment that
		// only ever asked for triage and report.
		{"both", PurposeAssistant, false},
		{"", PurposeAssistant, false},
		{"triage", PurposeAssistant, false},
		{PurposeAssistant, PurposeAssistant, true},

		// ...and an assistant-only model must not be pulled into triage or report work.
		{PurposeAssistant, "triage", false},
		{PurposeAssistant, "report", false},
	}
	for _, c := range cases {
		if got := LLMPurposeMatches(c.configured, c.want); got != c.ok {
			t.Errorf("LLMPurposeMatches(%q, %q) = %v, want %v", c.configured, c.want, got, c.ok)
		}
	}
}
