package assistant

import (
	"fmt"
	"sort"
	"strings"

	"deuswatch/internal/integrations"
)

// IntegrationsGuide renders the integration catalogue as instructions the assistant can walk an
// operator through.
//
// Generated from integrations.Catalog rather than written by hand, because a hand-written guide is
// wrong the first time somebody adds a connector and nobody finds out until an operator follows it.
// The catalogue is what actually builds the form, so this cannot drift from the screen the operator
// is looking at, and a new connector teaches the assistant about itself for free.
//
// Without this the assistant knew the Integrations page existed and nothing else, so asked for help
// adding one it could only refuse and point, which is the least useful thing an assistant can do.
func IntegrationsGuide() string {
	var b strings.Builder
	b.WriteString("HOW TO ADD AN INTEGRATION (walk them through it; you cannot do it for them)\n")
	b.WriteString("Integrations in the left nav, then Add, pick the Type, fill the fields, tick Enabled, Save. Most take effect within about a minute with no restart. Each type's panel has a \"See documentation\" link for the long version.\n")
	b.WriteString("Only name fields that exist for the type they asked about. Never invent a field, a value or a menu item.\n")

	types := make([]integrations.TypeInfo, len(integrations.Catalog))
	copy(types, integrations.Catalog)
	sort.Slice(types, func(i, j int) bool { return types[i].Type < types[j].Type })

	for _, t := range types {
		fmt.Fprintf(&b, "\n* %s (%s, category %s)\n", t.Label, t.Type, t.Category)
		for _, f := range t.Fields {
			fmt.Fprintf(&b, "  - %s", f.Label)
			var tags []string
			if f.Optional {
				tags = append(tags, "optional")
			}
			if f.Secret {
				tags = append(tags, "secret")
			}
			if len(tags) > 0 {
				fmt.Fprintf(&b, " [%s]", strings.Join(tags, ", "))
			}
			if len(f.Options) > 0 {
				fmt.Fprintf(&b, " choose one of: %s", strings.Join(f.Options, " / "))
			}
			// The help text carries the values that actually matter, the base URLs above all, and
			// is the one thing an operator cannot guess. Trimmed only where a type has written an
			// essay, since this whole block rides in every prompt.
			if h := strings.TrimSpace(f.Help); h != "" {
				fmt.Fprintf(&b, ". %s", clip(h, 220))
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// clip shortens at a word boundary so a truncated hint does not end mid-token and read as a value.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	if i := strings.LastIndexAny(cut, " ,;"); i > n/2 {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,;") + "..."
}

// howToWords are the verbs and nouns that mean "walk me through something", in English and
// Indonesian. Matched as substrings rather than whole words so that "menambahkan", "pasang" inside
// "memasang" and "configure"/"configuration" all land.
var howToWords = []string{
	"how ", "how'", "howto", "add ", "adding", "set up", "setup", "install", "configur", "connect",
	"enable", "integrat", "guide", "walk me", "steps", "where do i", "where can i",
	"cara", "pasang", "tambah", "atur", "aktif", "hubung", "sambung", "langkah", "gimana", "bagaimana",
}

// NeedsIntegrationsGuide decides whether to spend the catalogue on this message.
//
// The guide is around 4000 characters. Sending it every time would roughly double the prompt and
// push past the context window Ollama allocates by default, which truncates silently and degrades
// the assistant in a way nobody can see. So it rides along only when the operator is plainly asking
// how to set something up, which is the same deterministic-check approach the ban and whitelist
// commands use, for the same reason: cheap, predictable, and no model involved in the decision.
func NeedsIntegrationsGuide(msg string) bool {
	low := strings.ToLower(msg)
	for _, w := range howToWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	// A bare "ollama?" is a question about that connector often enough to be worth the catalogue.
	// Catalogue type keys are derived; product names are listed by hand because they are field
	// VALUES, and the values cannot be harvested safely: the same Options lists hold "report",
	// "both" and "true", which would fire on "show me the report". Going stale here costs only
	// that a one-word message misses the guide, which the next sentence from the operator fixes.
	for _, t := range integrations.Catalog {
		if strings.Contains(low, strings.ToLower(t.Type)) {
			return true
		}
	}
	for _, n := range connectorNames {
		if strings.Contains(low, n) {
			return true
		}
	}
	return false
}

var connectorNames = []string{
	"ollama", "anthropic", "claude", "openai", "gemini", "groq", "openrouter", "vllm",
	"telegram", "webhook", "smtp", "elasticsearch", "elastic", "wazuh", "virustotal", "nftables",
}

// AgentLine is one endpoint, flattened by the caller so this package stays free of a store import.
type AgentLine struct {
	Name, OS, Status, Version, Detail string
	Revoked                           bool
}

// MaxRosterLines caps the roster. A large fleet would otherwise crowd out everything else in the
// prompt; past this point the model gets counts per status instead of names, and is told so.
const MaxRosterLines = 40

// Roster renders the enrolled endpoints.
//
// The opening sentence is the load-bearing part. "This is the complete list" is what stops a model
// from adding plausible hostnames to it, and plausible is exactly what invented ones are: asked to
// name the online agents with no roster in context, it answered "test-server, web-server-1,
// db-server" on a fleet of one. A list the model is told is exhaustive is a list it can be caught
// contradicting; a vacuum is not.
func Roster(agents []AgentLine) string {
	var b strings.Builder
	if len(agents) == 0 {
		return "ENROLLED ENDPOINTS\nThere are no enrolled agents at all. If asked about agents, say exactly that.\n"
	}
	fmt.Fprintf(&b, "ENROLLED ENDPOINTS: %d in total, and this is the COMPLETE list.\n", len(agents))
	b.WriteString("Never name an agent that is not on it. If asked about one that is absent, say it is not enrolled.\n")
	b.WriteString("Status means: online = healthy; degraded = reporting a problem about itself; disconnected = missed heartbeats; stale = quiet over a day; unknown = enrolled but never checked in.\n")
	shown := agents
	if len(shown) > MaxRosterLines {
		shown = shown[:MaxRosterLines]
	}
	for _, a := range shown {
		fmt.Fprintf(&b, "- %s (%s): %s", a.Name, orUnknown(a.OS), a.Status)
		if a.Revoked {
			b.WriteString(", REVOKED")
		}
		if a.Version != "" {
			fmt.Fprintf(&b, ", agent %s", a.Version)
		}
		if d := strings.TrimSpace(a.Detail); d != "" {
			fmt.Fprintf(&b, ", reports: %s", clip(d, 120))
		}
		b.WriteString("\n")
	}
	if len(agents) > len(shown) {
		counts := map[string]int{}
		for _, a := range agents[len(shown):] {
			counts[a.Status]++
		}
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
		}
		fmt.Fprintf(&b, "...and %d more not listed individually (%s). Say so rather than guessing their names.\n",
			len(agents)-len(shown), strings.Join(parts, ", "))
	}
	return b.String()
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "OS unknown"
	}
	return s
}
