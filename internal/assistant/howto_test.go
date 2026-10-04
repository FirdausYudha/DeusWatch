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
