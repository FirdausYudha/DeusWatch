package assistant

import (
	"fmt"
	"net"
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

// RuleStats is the rule picture, flattened by the caller to keep this package store-free.
type RuleStats struct {
	Total, Enabled, Builtin, Custom, Aggregation int
	ByCategory                                   map[string]int
	CustomNames                                  []string
	Truncated                                    bool
}

// Rules renders the detection coverage.
//
// Added for the same reason as the roster: asked which rules were running, the model had nothing to
// read and answered by inventing a place to look ("Dashboard, bagian Rule Status", a section that
// does not exist). The counts answer the question that was actually asked, and the closing line
// tells the model what it CANNOT answer, which is what stops it from inventing a built-in rule name
// when someone asks whether a particular detection exists.
func Rules(s RuleStats) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DETECTION RULES: %d loaded, %d enabled (%d built-in, %d custom, %d of them counting/aggregation rules).\n",
		s.Total, s.Enabled, s.Builtin, s.Custom, s.Aggregation)
	if len(s.ByCategory) > 0 {
		keys := make([]string, 0, len(s.ByCategory))
		for k := range s.ByCategory {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if s.ByCategory[keys[i]] != s.ByCategory[keys[j]] {
				return s.ByCategory[keys[i]] > s.ByCategory[keys[j]]
			}
			return keys[i] < keys[j]
		})
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, s.ByCategory[k]))
		}
		fmt.Fprintf(&b, "Enabled per category: %s.\n", strings.Join(parts, ", "))
	}
	switch {
	case len(s.CustomNames) > 0:
		fmt.Fprintf(&b, "Custom rules (written here, not shipped): %s", strings.Join(s.CustomNames, "; "))
		if s.Truncated {
			b.WriteString("; and more")
		}
		b.WriteString(".\n")
	case s.Custom == 0:
		b.WriteString("No custom rules have been written yet; everything loaded ships with DeusWatch.\n")
	}
	b.WriteString("You do NOT have the names of the built-in rules, only these counts. If asked whether a specific detection exists, say you cannot see individual built-in rules and send them to the Rules page, which lists and searches all of them. Never guess a rule name.\n")
	return b.String()
}

// UIMap is where things live in the navigation.
//
// Hand-written, unlike the integrations guide, because the menu is defined in the React sidebar and
// there is no Go-side source to generate from. It is here because its absence produced confident
// fiction: told to point at a page, a model with no map invents a plausible one, and "Dashboard,
// Rule Status" is indistinguishable from a real instruction until the operator goes looking. The
// menu changes rarely and a stale line sends someone one click wide, which is a far better failure
// than a page that never existed.
const UIMap = `WHERE THINGS ARE IN THE UI (left navigation; use these names exactly, never invent a page or a section)
Monitoring & Operations: Dashboard (live posture, charts, attack map) | Response | Tickets | File Integrity (FIM events) | Snapshots (file versions, restore) | Report (periodic and AI summary)
The Response page has these tabs and no others: All, Recommended, Executed, Dismissed, Unbanned, Failed. Above them sit the progressive-ban policy, the kill-switch auto-approval, the IP whitelist, a manual "Ban an IP" box and the blocklist feed. Name one of these or none; a tab you half-remember from another product does not exist here.
Asset & Endpoint Management: Agents (enrol, status, uninstall) | Agent Health (vulnerability assessment and SCA)
Detection & Automation: Rules (every detection rule, searchable) | Decoders | Playbooks | Integrations (connectors: LLM, CTI, firewall, quarantine)
Administration & Access: Users | Workspaces | Tenants | Settings (2FA, notifications, retention, scoring weights, assistant persona)`

// OpsStats is the ticket queue, file-integrity activity and vulnerability posture, flattened by
// the caller.
type OpsStats struct {
	TicketsByStatus map[string]int
	TicketsOpenHigh int

	FIMRead      bool
	FileChanges  int
	TopFilePaths []string

	VulnAgents                      int
	VulnCritical, VulnHigh, VulnTot int
	WindowHours                     int
}

// Ops renders the three.
//
// Each section says explicitly when it has nothing, because the alternative is silence, and silence
// in a prompt is the vacuum that gets filled with invention. "No open tickets" and "I was not able
// to read the tickets" are different answers and the model must be able to give the right one.
func Ops(s OpsStats) string {
	var b strings.Builder

	b.WriteString("TICKETS: ")
	if len(s.TicketsByStatus) == 0 {
		b.WriteString("none have been created.\n")
	} else {
		// Workflow order, not alphabetical: "closed" first reads as the headline when the thing an
		// operator needs to hear is what is still open.
		parts := make([]string, 0, len(s.TicketsByStatus))
		seen := map[string]bool{}
		for _, k := range []string{"open", "in_progress", "resolved", "closed"} {
			if n := s.TicketsByStatus[k]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, k))
				seen[k] = true
			}
		}
		rest := make([]string, 0, 2)
		for k := range s.TicketsByStatus {
			if !seen[k] {
				rest = append(rest, k)
			}
		}
		sort.Strings(rest) // any status added later still appears, just after the known ones
		for _, k := range rest {
			parts = append(parts, fmt.Sprintf("%d %s", s.TicketsByStatus[k], k))
		}
		fmt.Fprintf(&b, "%s.", strings.Join(parts, ", "))
		if s.TicketsOpenHigh > 0 {
			fmt.Fprintf(&b, " %d of the open ones are high or critical severity.", s.TicketsOpenHigh)
		}
		b.WriteString(" You have counts only, not their titles or contents; send them to the Tickets page for those.\n")
	}

	switch {
	case !s.FIMRead:
		b.WriteString("FILE INTEGRITY: could not be read just now. Say so rather than reporting no changes.\n")
	case s.FileChanges == 0:
		fmt.Fprintf(&b, "FILE INTEGRITY: no watched file changed in the last %d hours.\n", s.WindowHours)
	default:
		fmt.Fprintf(&b, "FILE INTEGRITY: %d change events in the last %d hours.", s.FileChanges, s.WindowHours)
		if len(s.TopFilePaths) > 0 {
			fmt.Fprintf(&b, " Most changed: %s.", strings.Join(s.TopFilePaths, ", "))
		}
		b.WriteString("\n")
	}

	switch {
	case s.VulnAgents == 0:
		b.WriteString("VULNERABILITIES: no endpoint has been scanned yet, so there is no posture to report. Scanning runs from Agent Health.\n")
	default:
		fmt.Fprintf(&b, "VULNERABILITIES: %d findings across %d scanned endpoint(s): %d critical, %d high.",
			s.VulnTot, s.VulnAgents, s.VulnCritical, s.VulnHigh)
		b.WriteString(" Per-package detail is on the Agent Health page; you have totals only.\n")
	}
	return b.String()
}

// EnforcementStats is the response engine's state, flattened by the caller.
type EnforcementStats struct {
	Read         bool
	ActiveBlocks []string
	ActiveCount  int
	Pending      int
	Offenders    []string
	// Enforcing reports whether a ban reaches an actual firewall. Backends lists what it reaches.
	Enforcing bool
	Backends  []string
}

// Enforcement renders what is banned and whether banning does anything.
//
// The distinction in the last paragraph is the whole point and is easy to get wrong in both
// directions. DeusWatch records ban decisions whether or not a firewall is connected, so "banned"
// and "blocked" are different states. Telling an operator an address is blocked when nothing is
// enforcing it is the more expensive error: they stop looking at something still reaching them.
func Enforcement(s EnforcementStats) string {
	var b strings.Builder
	if !s.Read {
		return "RESPONSE / BANS: could not be read just now. Say so if asked whether something is blocked; do not assume it is not.\n"
	}

	b.WriteString("RESPONSE / BANS: ")
	switch s.ActiveCount {
	case 0:
		b.WriteString("no ban is currently in force.")
	default:
		fmt.Fprintf(&b, "%d ban(s) currently in force", s.ActiveCount)
		if len(s.ActiveBlocks) > 0 {
			fmt.Fprintf(&b, ": %s", strings.Join(s.ActiveBlocks, ", "))
			if s.ActiveCount > len(s.ActiveBlocks) {
				fmt.Fprintf(&b, " and %d more", s.ActiveCount-len(s.ActiveBlocks))
			}
		}
		b.WriteString(".")
	}
	if s.Pending > 0 {
		fmt.Fprintf(&b, " %d recommendation(s) are waiting for someone to approve or dismiss them on the Response page.", s.Pending)
	}
	b.WriteString("\n")

	if len(s.Offenders) > 0 {
		fmt.Fprintf(&b, "Addresses banned before, with how many times: %s. An address can be on this list and NOT currently banned, which means its ban expired. Check the in-force list above before saying something is unhandled.\n",
			strings.Join(s.Offenders, ", "))
	}

	if s.Enforcing {
		fmt.Fprintf(&b, "Enforcement is live through %s, so a ban reaches a real firewall.\n", strings.Join(s.Backends, ", "))
	} else {
		// Said in full because the difference decides what the operator does next, and the UI says
		// the same thing in a banner on the Response page rather than leaving it to be discovered.
		b.WriteString("IMPORTANT: enforcement is NOT configured. DeusWatch is recording these ban decisions but nothing is pushing them to a firewall, so the addresses above are FLAGGED, not blocked, and traffic from them still arrives. Never tell the operator an address is blocked while this is the case. To change it, set RESPONSE_LIVE=1 and connect a responder (MikroTik, CrowdSec or agent nftables) under Integrations, or enable the blocklist feed on the Response page for an external firewall to pull.\n")
	}
	return b.String()
}

// Dossier is one address the operator named, looked up directly.
type Dossier struct {
	IP                       string
	Found, Blocked, Listed   bool
	Offenses, Total, Pending int
	LastStatus, LastReason   string
	LastAgent                string
	Events24h                int
	BlockedUntil, LastSeen   string
}

// IPReport renders what is known about an address.
//
// This exists because a top-N offender list cannot answer a question about an arbitrary address.
// Asked whether 72.167.227.34 was dangerous, the assistant said it had no information while that
// address sat in the first row of the Response page with four offences against it: dozens of
// addresses were tied on the same count and the one being asked about fell outside the slice. A
// list sized to fit a prompt will always have that failure; looking up the address named does not.
func IPReport(d Dossier) string {
	var b strings.Builder
	fmt.Fprintf(&b, "LOOKUP FOR %s (the operator named this address; this is its full history, use it)\n", d.IP)
	if !d.Found {
		fmt.Fprintf(&b, "No response action and no event in the last 24 hours involves %s. It is genuinely unknown to this deployment, which is a real answer: say so rather than hedging.\n", d.IP)
		if d.Listed {
			b.WriteString("It IS on the whitelist, so the response engine would refuse to ban it even if asked.\n")
		}
		return b.String()
	}
	fmt.Fprintf(&b, "Response history: %d total decision(s), %d executed ban(s), %d waiting for approval.", d.Total, d.Offenses, d.Pending)
	if d.LastReason != "" {
		fmt.Fprintf(&b, " Most recent reason: %q.", d.LastReason)
	}
	if d.LastAgent != "" {
		fmt.Fprintf(&b, " Seen against agent %s.", d.LastAgent)
	}
	if d.LastSeen != "" {
		fmt.Fprintf(&b, " Last decision %s.", d.LastSeen)
	}
	b.WriteString("\n")
	if d.Blocked {
		fmt.Fprintf(&b, "A ban is currently in force%s.\n", until(d.BlockedUntil))
	} else if d.Offenses > 0 {
		b.WriteString("No ban is in force right now, even though it has been banned before: the previous one expired. Those are different states and the operator usually means the current one.\n")
	} else {
		b.WriteString("It has never actually been banned; the decisions above are recommendations nobody approved.\n")
	}
	if d.Events24h > 0 {
		fmt.Fprintf(&b, "It generated %d event(s) in the last 24 hours, so it is active right now.\n", d.Events24h)
	}
	if d.Listed {
		b.WriteString("It is on the WHITELIST, so the response engine refuses to ban it. If the operator wants it banned they have to remove the whitelist entry first.\n")
	}
	return b.String()
}

func until(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return ", until " + s
}

// MentionedIPs returns the addresses named in a message, so each can be looked up. Capped: a paste
// of a log excerpt should not turn into twenty queries.
func MentionedIPs(msg string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 3)
	for _, loc := range reAddr.FindAllStringIndex(msg, -1) {
		if !addressBoundaryOK(msg, loc[0], loc[1]) {
			continue
		}
		m := msg[loc[0]:loc[1]]
		if strings.Contains(m, "/") {
			continue // a CIDR is not an address to look up
		}
		ip := net.ParseIP(m)
		if ip == nil || ip.IsUnspecified() || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip.String())
		if len(out) == 3 {
			break
		}
	}
	return out
}
