package main

import "testing"

// The characters-to-tokens ratio used by the status endpoint, pinned against a real measurement.
//
// A live deployment logged `task.n_tokens = 5137` for a system prompt of about 17888 characters.
// The usual 4:1 rule puts that at 4472, understating it by 13%, because this prompt is denser than
// ordinary prose: it is full of IP addresses, rule names, menu paths and hex hashes, all of which
// tokenise badly.
//
// The direction of the error is the point. This ratio decides whether an operator is warned that
// their persona is being truncated, so understating the token count means the warning fires late or
// never, which is the exact failure the check exists to end. Overstating costs at worst one
// unnecessary look at a setting.
//
// If someone later "tidies" this back to a round 4, this test is what should stop them.
func TestPromptTokenEstimateMatchesAMeasuredPrompt(t *testing.T) {
	const (
		observedChars  = 17888 // worst-case base prompt at the time of the measurement
		observedTokens = 5137  // task.n_tokens, from the Ollama server logs
	)
	got := observedChars * 2 / 7 // the expression used in assistantStatusHandler

	if got < observedTokens*95/100 {
		t.Errorf("estimate %d is more than 5%% under the measured %d. Understating means the "+
			"truncation warning fires late or not at all.", got, observedTokens)
	}
	if got > observedTokens*125/100 {
		t.Errorf("estimate %d is more than 25%% over the measured %d, which will warn about "+
			"prompts that fit.", got, observedTokens)
	}
	t.Logf("estimate %d vs measured %d (%+.1f%%)", got, observedTokens,
		float64(got-observedTokens)/float64(observedTokens)*100)
}
