package assistant

import (
	"strings"
	"testing"
)

func TestParseWindow(t *testing.T) {
	for msg, want := range map[string]int{
		"apa yang terjadi 7 hari terakhir?":    24 * 7,
		"anything odd in the last 3 days?":     24 * 3,
		"cek 6 jam terakhir":                   6,
		"what happened last week":              24 * 7,
		"ada yang aneh minggu lalu?":           24 * 7,
		"bandingkan 2 minggu":                  24 * 14,
		"sebulan terakhir gimana?":             24 * 30,
		"anything unusual in the last 1 hour?": 1,
	} {
		got, ok := ParseWindow(msg)
		if !ok || got != want {
			t.Errorf("%q: got %d (ok=%v), want %d", msg, got, ok, want)
		}
	}
	// No window named means the caller keeps its default; guessing one would silently answer about
	// a different period than the operator meant, and the answer would not show it.
	for _, msg := range []string{"hello", "which agents are online?", "ban 1.2.3.4"} {
		if h, ok := ParseWindow(msg); ok {
			t.Errorf("%q should not name a window, got %d", msg, h)
		}
	}
	// An absurd window must be clamped rather than driving a query across all of history.
	if h, _ := ParseWindow("show me 9999 days"); h != MaxWindowHours {
		t.Errorf("9999 days should clamp to %d, got %d", MaxWindowHours, h)
	}
}

func TestNeedsComparison(t *testing.T) {
	for _, m := range []string{
		"ada anomali ngga minggu ini?", "anything unusual today?", "is this a spike?",
		"apakah ada lonjakan?", "compare with last week", "something different?",
	} {
		if !NeedsComparison(m) {
			t.Errorf("%q should pull in the baseline", m)
		}
	}
	// The baseline doubles the report queries; a plain description does not need it.
	for _, m := range []string{"hello", "which agents are online?", "what is a playbook?"} {
		if NeedsComparison(m) {
			t.Errorf("%q should NOT pull in the baseline", m)
		}
	}
}

func TestTrendPhrasesTheArithmetic(t *testing.T) {
	cur := Window{Events: 412, Alerts: 93,
		BySeverity:   []Count{{Label: "high", Count: 40}, {Label: "low", Count: 53}},
		TopSourceIPs: []Count{{Label: "45.134.26.9", Count: 49}, {Label: "8.8.4.4", Count: 12}},
		TopRules:     []Count{{Label: "SSH Brute Force", Count: 60}},
		TopAgents:    []Count{{Label: "web-01", Count: 93}}}
	prev := Window{Events: 93, Alerts: 93,
		BySeverity:   []Count{{Label: "high", Count: 10}, {Label: "low", Count: 52}},
		TopSourceIPs: []Count{{Label: "45.134.26.9", Count: 44}, {Label: "1.1.1.1", Count: 9}},
		TopRules:     []Count{{Label: "SSH Brute Force", Count: 58}},
		TopAgents:    []Count{{Label: "web-01", Count: 90}, {Label: "db-01", Count: 11}}}

	g := Trend(cur, prev, 24)
	for _, want := range []string{
		"93 -> 412 (up 343%)",     // the model must never have to do this division itself
		"high 10 -> 40 (up 300%)", // a real severity shift
		"8.8.4.4 (12)",            // newly appeared
		"1.1.1.1 (9)",             // stopped
		"db-01 (11)",              // went quiet, which matters as much as getting noisy
		"A big number is not an anomaly; a big CHANGE is",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("trend missing %q:\n%s", want, g)
		}
	}
	// Alerts were flat and "low" moved 2%: neither is a finding, and printing them would fill the
	// block with non-findings until the operator stops reading it.
	if !strings.Contains(g, "Alerts: 93 in both periods") && !strings.Contains(g, "Alerts: 93 -> 93") {
		t.Errorf("a flat figure should be stated as flat:\n%s", g)
	}
	if strings.Contains(g, "low 52 -> 53") {
		t.Errorf("a 2%% move is noise and must not be printed:\n%s", g)
	}
}

// Percentages off a zero base are meaningless, and "up infinity%" is the kind of output that makes
// an operator stop trusting the whole block.
func TestTrendHandlesZeroBaselines(t *testing.T) {
	g := Trend(Window{Events: 50}, Window{Events: 0}, 24)
	if !strings.Contains(g, "0 -> 50 (new activity; there was none before)") {
		t.Errorf("a zero baseline needs words, not a division:\n%s", g)
	}
	g = Trend(Window{Events: 0}, Window{Events: 50}, 24)
	if !strings.Contains(g, "50 -> 0 (stopped entirely)") {
		t.Errorf("activity stopping needs saying plainly:\n%s", g)
	}
}
