package assistant

import (
	"regexp"
	"strings"
	"testing"

	"deuswatch/internal/detect/sigma"
)

// The examples in the guide are what the model copies. If one of them stops parsing, every rule
// drafted from it is rejected on save and the operator sees a parse error they cannot act on, so
// they are checked against the real engine rather than trusted to stay correct.
func TestRuleAuthoringGuideExamplesParse(t *testing.T) {
	// Each example runs from its "title:" to the blank line before the next prose paragraph.
	blocks := regexp.MustCompile(`(?s)title: .*?\n\n`).FindAllString(RuleAuthoringGuide+"\n\n", -1)
	if len(blocks) < 2 {
		t.Fatalf("expected the single-event and aggregation examples, found %d", len(blocks))
	}
	for i, b := range blocks {
		kind, err := sigma.Classify([]byte(strings.TrimSpace(b)))
		if err != nil {
			t.Errorf("example %d does not parse: %v\n%s", i+1, err, b)
			continue
		}
		t.Logf("example %d parses as %s", i+1, kind)
	}
}

// The field list is the other thing the model copies verbatim. A name that the matcher never sees
// produces a rule that saves cleanly and then never fires, which is the worst failure of the three
// because nothing reports it.
func TestRuleAuthoringGuideNamesRealFields(t *testing.T) {
	for _, f := range []string{
		"event.dataset", "event.category", "event.outcome", "event.original",
		"source.ip", "user.name", "process.command_line", "file.path", "host.name",
	} {
		if !strings.Contains(RuleAuthoringGuide, f) {
			t.Errorf("guide omits the %q field", f)
		}
	}
	// A rule with no logsource runs against every event, which is a performance and noise trap.
	if !strings.Contains(RuleAuthoringGuide, "Always set one") {
		t.Error("guide no longer insists on a logsource")
	}
}

func TestExtractRuleYAML(t *testing.T) {
	fenced := "Here you go.\n\n```yaml\ntitle: Test\ndetection:\n  selection:\n    a: b\n  condition: selection\n```\nAnything after."
	got, ok := ExtractRuleYAML(fenced)
	if !ok || !strings.HasPrefix(got, "title: Test") || strings.Contains(got, "Anything after") {
		t.Errorf("fenced extraction wrong: ok=%v\n%s", ok, got)
	}

	// Models wrap code even when asked not to, but they also sometimes do not.
	bare := "title: Test\ndetection:\n  keywords:\n    - 'x'\n  condition: keywords"
	if _, ok := ExtractRuleYAML(bare); !ok {
		t.Error("unfenced rule should still be recognised")
	}

	// Ordinary prose must never be mistaken for a draft; a card offering to save an English
	// sentence as a detection rule is worse than no card.
	for _, s := range []string{
		"I can write that rule for you, what should it catch?",
		"title: that is not a rule", // has title: but no detection:
		"",
	} {
		if y, ok := ExtractRuleYAML(s); ok {
			t.Errorf("%q should not yield a draft, got %q", s, y)
		}
	}

	// A runaway generation must not become a rule that slows the matcher on every event.
	huge := "```yaml\ntitle: x\ndetection: y\n" + strings.Repeat("- 'a'\n", MaxRuleYAML) + "```"
	if _, ok := ExtractRuleYAML(huge); ok {
		t.Error("an oversized draft should be refused")
	}
}

func TestNeedsRuleAuthoring(t *testing.T) {
	for _, m := range []string{
		"buatkan rule untuk mendeteksi upload webshell",
		"create a rule for failed sudo attempts",
		"write a sigma rule that catches nmap",
		"bikin aturan deteksi untuk login root",
		// Phrasings the original list missed.
		"a signature for this malware behaviour",
		"rule untuk port scan",
		"an alert for brute force",
	} {
		if !NeedsRuleAuthoring(m) {
			t.Errorf("%q should pull in the authoring guide", m)
		}
	}
	for _, m := range []string{"what happened today?", "hello", "which agents are online?"} {
		if NeedsRuleAuthoring(m) {
			t.Errorf("%q should NOT pull in the authoring guide", m)
		}
	}
}
