package assistant

import (
	"strings"
	"testing"
)

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
//
// THE PERSONA IS MEASURED SEPARATELY, and that split is the point of this file.
//
// A persona is operator-supplied and replaces the built-in one wholesale, so it is the one part of
// the prompt the project does not control. Measuring the total against the built-in default meant
// measuring a deployment almost nobody runs: the default is ~5.4k chars and the shipped Mia persona
// is 8.3k, so a budget that passed here was already 3k over on a real install. Worse, the number
// moved whenever the default persona was edited, which has nothing to do with whether a new block
// is affordable.
//
// So the framework ceiling covers what this project ships and is what a new block spends. The
// window ceilings then add the LARGEST persona anyone can actually select, which is what a real
// prompt costs.
const (
	// Everything except the persona: capability map, navigation map, schema guide, reference blocks
	// and the scaffolding around them. This is the number to look at when adding a block.
	maxFrameworkChars = 9500
	// Framework plus the biggest persona on offer. This is what a message really costs.
	maxBasePromptChars   = 19000
	maxGuidedPromptChars = 27000 // plus a setup or rule-authoring guide
	// The pathological case: a conceptual question that also asks for a rule, names a window and
	// asks what changed. Rare, but it has to fit, or that one message silently loses its tail.
	maxWorstCasePromptChars = 35000
)

// worstPersona returns the largest persona an operator can pick from the UI. Tests budget against
// this rather than the default, because picking a character from the list is one click and the
// prompt grows by the difference.
func worstPersona(t *testing.T) string {
	t.Helper()
	worst := DefaultPersona
	for _, p := range Personas() {
		if len(p.Text) > len(worst) {
			worst = p.Text
		}
	}
	return worst
}

// frameworkChars is the prompt with the persona's own length subtracted, which works because
// SystemPrompt writes the persona verbatim and first.
func frameworkChars(t *testing.T, c Context) int {
	t.Helper()
	p := worstPersona(t)
	full := len(SystemPrompt(p, c))
	if !strings.HasPrefix(SystemPrompt(p, c), p) {
		t.Fatal("the persona is no longer written verbatim at the front, so this subtraction is wrong")
	}
	return full - len(p)
}

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

// What this project ships, with the operator's persona taken out. This is the one that should fail
// when a block is added, and the one whose number means something to whoever added it.
func TestFrameworkWithinBudget(t *testing.T) {
	c := realisticContext()
	c.HowTo = SQLGuide() // attached to everything that is not small talk
	n := frameworkChars(t, c)
	t.Logf("framework %d chars (~%d tokens), persona excluded", n, n/4)
	if n > maxFrameworkChars {
		t.Errorf("the framework is %d chars, over the %d budget. Gate the newest block behind a "+
			"keyword check rather than raising this: every message pays for it in latency, and the "+
			"operator's persona is spent on top of it.", n, maxFrameworkChars)
	}
}

func TestBasePromptWithinBudget(t *testing.T) {
	c := realisticContext()
	c.HowTo = SQLGuide() // attached to everything that is not small talk
	n := len(SystemPrompt(worstPersona(t), c))
	t.Logf("base prompt %d chars (~%d tokens), with the largest selectable persona", n, n/4)
	if n > maxBasePromptChars {
		t.Errorf("base prompt is %d chars, over the %d budget. Gate the newest block behind a "+
			"keyword check rather than raising this: every message pays for it in latency.", n, maxBasePromptChars)
	}
}

// The ceiling that actually bites in production. A persona may be anything up to
// store.MaxPersonaLen, so the framework has to leave room for one that large inside the context
// window the deployment runs, or the server truncates from the front and the persona goes first.
// That is exactly the symptom reported after a model switch: character gone, data answers intact.
func TestFrameworkLeavesRoomForAMaximalPersona(t *testing.T) {
	c := realisticContext()
	c.HowTo = SQLGuide()
	n := frameworkChars(t, c) + maxPersonaLen
	t.Logf("framework + a maximum-length persona = %d chars (~%d tokens)", n, n/4)
	// 16384 is the context length the docs tell operators to configure. A quarter of it is left for
	// the conversation and the reply, so the system prompt may claim at most three quarters.
	const budget = 16384 * 3 / 4 * 4 // tokens -> chars, at the usual 4:1
	if n > budget {
		t.Errorf("framework + a %d-char persona is %d chars (~%d tokens), over the ~%d the "+
			"documented 16384-token window leaves for a system prompt. An operator who writes a "+
			"long character gets it silently cut off the front.", maxPersonaLen, n, n/4, budget)
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
	n := len(SystemPrompt(worstPersona(t), c))
	t.Logf("worst-case prompt %d chars (~%d tokens)", n, n/4)
	if n > maxWorstCasePromptChars {
		t.Errorf("worst-case prompt is %d chars, over the %d budget", n, maxWorstCasePromptChars)
	}
}

func TestGuidedPromptWithinBudget(t *testing.T) {
	c := realisticContext()
	// The worst realistic case: a how-to question that also asks for a rule.
	c.HowTo = IntegrationsGuide() + "\n" + RuleAuthoringGuide
	n := len(SystemPrompt(worstPersona(t), c))
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
