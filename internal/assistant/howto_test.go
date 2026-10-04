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
