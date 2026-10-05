package assistant

import (
	"strings"
	"testing"

	"deuswatch/internal/integrations"
)

// The guide is generated from the catalogue so it cannot drift from the form the operator is
// looking at. If a connector is ever added without appearing here, the assistant will confidently
// describe a page that no longer matches.
func TestIntegrationsGuideCoversEveryType(t *testing.T) {
	g := IntegrationsGuide()
	for _, ti := range integrations.Catalog {
		if !strings.Contains(g, ti.Type) {
			t.Errorf("guide is missing the %q type", ti.Type)
		}
		for _, f := range ti.Fields {
			if !strings.Contains(g, f.Label) {
				t.Errorf("guide is missing the %q field of %q", f.Label, ti.Type)
			}
		}
	}
	// The values an operator cannot guess are the whole point of carrying the help text.
	if !strings.Contains(g, "host.docker.internal:11434") {
		t.Errorf("guide dropped the Ollama base URL, which is the field nobody can guess:\n%s", g)
	}
	// Guards against the model inventing a field when a type has few of them.
	if !strings.Contains(g, "Never invent a field") {
		t.Errorf("guide lost its no-invention rule:\n%s", g)
	}
}

func TestNeedsIntegrationsGuide(t *testing.T) {
	for _, msg := range []string{
		"can you assist me to add new integration, for example new LLM to integrate?",
		"how do I connect Telegram?",
		"cara pasang ollama gimana?",
		"bagaimana menambahkan integrasi baru",
		"setup abuseipdb",
		"aktifkan notifikasi telegram",
		"ollama", // a bare connector name is a question about it often enough to be worth the cost
	} {
		if !NeedsIntegrationsGuide(msg) {
			t.Errorf("%q should pull in the setup guide", msg)
		}
	}
	// The guide roughly doubles the prompt, so ordinary SOC questions must not drag it along.
	for _, msg := range []string{
		"what happened in the last 24 hours?",
		"is 45.134.26.9 dangerous?",
		"hello",
		"which agent is noisiest?",
	} {
		if NeedsIntegrationsGuide(msg) {
			t.Errorf("%q should NOT pull in the setup guide", msg)
		}
	}
}

// The roster exists to close a vacuum the model filled with invented hostnames, so the sentence
// that tells it the list is exhaustive matters more than the list itself.
func TestRosterStatesItIsComplete(t *testing.T) {
	g := Roster([]AgentLine{
		{Name: "test-server", OS: "linux", Status: "online", Version: "v2.23.0"},
		{Name: "old-box", OS: "linux", Status: "stale", Revoked: true},
	})
	for _, want := range []string{
		"COMPLETE list",
		"Never name an agent that is not on it",
		"test-server (linux): online, agent v2.23.0",
		"old-box (linux): stale, REVOKED",
		"2 in total",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("roster missing %q:\n%s", want, g)
		}
	}
}

// An empty fleet must read as "there are none", not as a missing section the model fills in.
func TestRosterEmptyFleetSaysSo(t *testing.T) {
	if g := Roster(nil); !strings.Contains(g, "no enrolled agents at all") {
		t.Errorf("empty roster should say so explicitly:\n%s", g)
	}
}

// A large fleet must not crowd out the rest of the prompt, and the model has to be told that the
// names it cannot see exist rather than being left to infer the fleet is smaller than it is.
func TestRosterCapsLongFleets(t *testing.T) {
	many := make([]AgentLine, MaxRosterLines+5)
	for i := range many {
		many[i] = AgentLine{Name: "agent", Status: "online"}
	}
	g := Roster(many)
	if !strings.Contains(g, "5 more not listed individually") || !strings.Contains(g, "5 online") {
		t.Errorf("capped roster must account for the remainder:\n%s", g)
	}
}

func TestRulesDigestAnswersAndAdmitsItsLimit(t *testing.T) {
	g := Rules(RuleStats{
		Total: 824, Enabled: 820, Builtin: 812, Custom: 12, Aggregation: 15,
		ByCategory:  map[string]int{"judi": 406, "fim": 156, "custom": 12},
		CustomNames: []string{"Webshell upload attempt", "Sudo brute force"},
		Truncated:   true,
	})
	for _, want := range []string{
		"824 loaded, 820 enabled",
		"812 built-in, 12 custom",
		"judi 406", // ordered by count, not alphabetically
		"Webshell upload attempt; Sudo brute force; and more",
		// Without this sentence the model answers "is there a rule for X?" by inventing one.
		"cannot see individual built-in rules",
		"Never guess a rule name",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("digest missing %q:\n%s", want, g)
		}
	}
}

// A fresh install must not read as though custom rules exist but were omitted.
func TestRulesDigestNoCustomRules(t *testing.T) {
	g := Rules(RuleStats{Total: 812, Enabled: 812, Builtin: 812})
	if !strings.Contains(g, "No custom rules have been written yet") {
		t.Errorf("digest should say so when there are none:\n%s", g)
	}
}

// Every page the assistant is allowed to send someone to has to be a page that exists; this is the
// list it reads instead of inventing one.
func TestUIMapNamesTheRealPages(t *testing.T) {
	for _, page := range []string{
		"Dashboard", "Response", "Tickets", "File Integrity", "Snapshots", "Report",
		"Agents", "Agent Health", "Rules", "Decoders", "Playbooks", "Integrations",
		"Users", "Workspaces", "Tenants", "Settings",
	} {
		if !strings.Contains(UIMap, page) {
			t.Errorf("UI map omits the %q page", page)
		}
	}
	if !strings.Contains(UIMap, "never invent a page") {
		t.Error("UI map lost its no-invention rule")
	}
}

func TestOpsRendersAllThree(t *testing.T) {
	g := Ops(OpsStats{
		TicketsByStatus: map[string]int{"open": 3, "closed": 7}, TicketsOpenHigh: 2,
		FIMRead: true, FileChanges: 14, TopFilePaths: []string{"/etc/passwd (9)"},
		VulnAgents: 1, VulnCritical: 4, VulnHigh: 31, VulnTot: 287, WindowHours: 24,
	})
	for _, want := range []string{
		"3 open, 7 closed", "2 of the open ones are high or critical",
		"14 change events in the last 24 hours", "/etc/passwd (9)",
		"287 findings across 1 scanned endpoint(s): 4 critical, 31 high",
		// Each section must name its own ceiling or the model fills past it.
		"not their titles or contents", "you have totals only",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("ops digest missing %q:\n%s", want, g)
		}
	}
}

// The distinction that matters most: a failed read must never render as a quiet night. That
// confusion is the exact silent failure the whole platform exists to prevent.
func TestOpsSeparatesEmptyFromUnreadable(t *testing.T) {
	quiet := Ops(OpsStats{FIMRead: true, WindowHours: 24})
	if !strings.Contains(quiet, "no watched file changed") {
		t.Errorf("a genuinely quiet window should say so:\n%s", quiet)
	}
	broken := Ops(OpsStats{FIMRead: false, WindowHours: 24})
	if !strings.Contains(broken, "could not be read") || strings.Contains(broken, "no watched file changed") {
		t.Errorf("an unreadable FIM section must not read as quiet:\n%s", broken)
	}
	if !strings.Contains(quiet, "none have been created") {
		t.Errorf("no tickets should say so explicitly:\n%s", quiet)
	}
	if !strings.Contains(quiet, "no endpoint has been scanned yet") {
		t.Errorf("an unscanned fleet should say so rather than implying zero findings:\n%s", quiet)
	}
}

// The question that produced this block: "is 142.93.121.216 already in the blocklist?" was answered
// "no" while the Response page showed it banned four times. Being on the offender list and not
// currently banned are different states, and so are banned and actually blocked.
func TestEnforcementSeparatesBannedFromBlocked(t *testing.T) {
	notLive := Enforcement(EnforcementStats{
		Read: true, ActiveCount: 1, ActiveBlocks: []string{"142.93.121.216"},
		Offenders: []string{"142.93.121.216 (4 bans)"}, Pending: 2,
	})
	for _, want := range []string{
		"1 ban(s) currently in force: 142.93.121.216",
		"142.93.121.216 (4 bans)",
		"2 recommendation(s) are waiting",
		// The distinction that decides what the operator does next.
		"FLAGGED, not blocked",
		"Never tell the operator an address is blocked while this is the case",
		"RESPONSE_LIVE=1",
	} {
		if !strings.Contains(notLive, want) {
			t.Errorf("enforcement block missing %q:\n%s", want, notLive)
		}
	}

	live := Enforcement(EnforcementStats{Read: true, Enforcing: true, Backends: []string{"mikrotik"}})
	if !strings.Contains(live, "live through mikrotik") || strings.Contains(live, "FLAGGED, not blocked") {
		t.Errorf("a live deployment must not carry the not-enforcing warning:\n%s", live)
	}
}

// An unreadable ban list must never render as "nothing is banned": that is the one wrong answer
// that makes an operator stop looking at a live attacker.
func TestEnforcementUnreadableIsNotEmpty(t *testing.T) {
	g := Enforcement(EnforcementStats{Read: false})
	if !strings.Contains(g, "could not be read") || strings.Contains(g, "no ban is currently in force") {
		t.Errorf("an unreadable ban list must not read as empty:\n%s", g)
	}
}

// Mia invented a "Ban queue" section on the Response page. The real tabs are listed so she does not
// have to guess, and the guard is that the list stays complete.
func TestUIMapNamesTheResponseTabs(t *testing.T) {
	for _, tab := range []string{"All", "Recommended", "Executed", "Dismissed", "Unbanned", "Failed"} {
		if !strings.Contains(UIMap, tab) {
			t.Errorf("UI map omits the Response tab %q", tab)
		}
	}
}
