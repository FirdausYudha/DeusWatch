package assistant

import "testing"

func TestNeedsPrimer(t *testing.T) {
	for _, m := range []string{
		"what is a degraded agent?",
		"apa itu aggregation rule?",
		"jelaskan severity di DeusWatch",
		"how does the response engine work?",
		// Phrasings the original list missed.
		"apa fungsi worker?",
		"containment untuk apa sih?",
		"gunanya whitelist apa?",
	} {
		if !NeedsPrimer(m) {
			t.Errorf("%q should pull in the primer", m)
		}
	}
	// Operational questions ("what happened") must not drag the concept primer along.
	for _, m := range []string{"what happened today?", "which agents are online?", "hello"} {
		if NeedsPrimer(m) {
			t.Errorf("%q should NOT pull in the primer", m)
		}
	}
}
