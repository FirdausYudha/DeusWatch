package assistant

import "testing"

// Prompt budget.
//
// Every block added here is paid for on EVERY message, twice over: once in context window, and once
// in time, because a local model on CPU reads a prompt at tens of tokens a second. A 2000-token
// prompt already cost over two minutes on an 8B model and produced "context deadline exceeded" in
// the chat panel, so this is not a theoretical limit.
//
// The ceilings leave room under Ollama's default context for the conversation and the reply. When
// one of these fails, the answer is usually to gate the new block behind a keyword check the way
// the setup and rule-authoring guides are, not to raise the number.
const (
	// The schema guide now rides on nearly every message, so "base" includes it. Raised from 12000
	// when the gate was inverted: withholding the guide saved tokens and cost answers, which is the
	// wrong trade in a tool whose job is answering.
	maxBasePromptChars   = 15000 // every message pays this
	maxGuidedPromptChars = 24000 // plus a setup or rule-authoring guide
	// The pathological case: a conceptual question that also asks for a rule, names a window and
	// asks what changed. Rare, but it has to fit, or that one message silently loses its tail.
	maxWorstCasePromptChars = 32000
)

func realisticContext() Context {
	return Context{
		WindowHours: 24,
		Data:        "Security data for the last 24 hours.\nTotal events: 101034. Total alerts: 93.\nSeverity breakdown: medium: 37, low: 56.\nTop source IPs: 45.134.26.9: 49, 142.93.121.216: 44.\n",
		WorkerAlive: true,
		Operator:    "Firdaus",
		LocalTime:   "Sunday 5 October, around 21:00",
		UI:          UIMap,
		Roster:      Roster([]AgentLine{{Name: "test-server", OS: "linux", Status: "online", Version: "v2.26.0"}}),
		Rules: Rules(RuleStats{Total: 824, Enabled: 820, Builtin: 812, Custom: 12, Aggregation: 15,
			ByCategory: map[string]int{"judi": 406, "fim": 156, "endpoint": 89, "deface": 125, "custom": 12}}),
		Remembered: Memories([]string{"Prefers to be called Firdaus", "SSH is on port 2222, not 22"}),
		Threats: Threats(ThreatStats{Read: true, Malicious: 1, Suspicious: 3,
			RecentNames: []string{"xmrig (malicious)"}, WindowHours: 24}),
		Accounts: Users([]UserLine{{Username: "admin", Role: "admin"}}, true),
		Enforcement: Enforcement(EnforcementStats{
			Read: true, ActiveCount: 1, ActiveBlocks: []string{"142.93.121.216"},
			Offenders: []string{"142.93.121.216 (4 bans)"}, Pending: 2,
		}),
		Ops: Ops(OpsStats{
			TicketsByStatus: map[string]int{"open": 3, "closed": 7}, TicketsOpenHigh: 1,
			FIMRead: true, FileChanges: 14, TopFilePaths: []string{"/etc/passwd (9)"},
			VulnAgents: 1, VulnCritical: 4, VulnHigh: 31, VulnTot: 287, WindowHours: 24,
		}),
	}
}

func TestBasePromptWithinBudget(t *testing.T) {
	c := realisticContext()
	c.HowTo = SQLGuide() // attached to everything that is not small talk
	n := len(SystemPrompt("", c))
	t.Logf("base prompt %d chars (~%d tokens)", n, n/4)
	if n > maxBasePromptChars {
		t.Errorf("base prompt is %d chars, over the %d budget. Gate the newest block behind a "+
			"keyword check rather than raising this: every message pays for it in latency.", n, maxBasePromptChars)
	}
}

// Everything gated, all at once.
func TestWorstCasePromptWithinBudget(t *testing.T) {
	c := realisticContext()
	c.HowTo = IntegrationsGuide() + "\n" + RuleAuthoringGuide + "\n" + Primer
	c.Trend = Trend(
		Window{Events: 412, Alerts: 93, BySeverity: []Count{{Label: "high", Count: 40}},
			TopSourceIPs: []Count{{Label: "45.134.26.9", Count: 49}}},
		Window{Events: 93, Alerts: 93, BySeverity: []Count{{Label: "high", Count: 10}},
			TopSourceIPs: []Count{{Label: "1.1.1.1", Count: 9}}}, 24)
	n := len(SystemPrompt("", c))
	t.Logf("worst-case prompt %d chars (~%d tokens)", n, n/4)
	if n > maxWorstCasePromptChars {
		t.Errorf("worst-case prompt is %d chars, over the %d budget", n, maxWorstCasePromptChars)
	}
}

func TestGuidedPromptWithinBudget(t *testing.T) {
	c := realisticContext()
	// The worst realistic case: a how-to question that also asks for a rule.
	c.HowTo = IntegrationsGuide() + "\n" + RuleAuthoringGuide
	n := len(SystemPrompt("", c))
	t.Logf("guided prompt %d chars (~%d tokens)", n, n/4)
	if n > maxGuidedPromptChars {
		t.Errorf("guided prompt is %d chars, over the %d budget", n, maxGuidedPromptChars)
	}
}

// The cacheable prefix is what makes a follow-up message fast: llama.cpp reuses the KV state of a
// prompt prefix, and re-evaluates everything from the first differing byte. The persona and the
// navigation map are identical between messages, so they must come BEFORE anything that changes.
func TestStablePrefixComesFirst(t *testing.T) {
	c := realisticContext()
	a := SystemPrompt("", c)
	c.LocalTime = "Monday 6 October, around 09:00"
	c.Data = "Security data for the last 24 hours.\nTotal events: 2. Total alerts: 0.\n"
	b := SystemPrompt("", c)

	shared := 0
	for shared < len(a) && shared < len(b) && a[shared] == b[shared] {
		shared++
	}
	if min := len(DefaultPersona) + len(UIMap); shared < min {
		t.Errorf("only %d chars are shared between two messages, expected at least %d (persona + "+
			"UI map). Something volatile moved above the stable blocks, which costs a full prompt "+
			"re-evaluation on every message.", shared, min)
	}
	t.Logf("cacheable prefix: %d of %d chars (%d%%)", shared, len(a), shared*100/len(a))
}
