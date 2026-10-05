package assistant

import (
	"fmt"
	"net"
	"regexp"
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
	HasScore                 bool
	Score, Anomaly           int
	Band                     string
	// Activity: what the address DID, as opposed to what was decided about it.
	Events                   int
	FirstSeen, LastSeenEvent string
	Rules, Agents, Countries []string
	// Reputation, from the CTI cache or a live lookup. Source says which, because a figure from
	// three weeks ago and one from ten seconds ago deserve different confidence.
	HasCTI                bool
	Abuse, OTX            int
	CTICountry, CTISource string
	CTIAge                string
	CTILive               bool
	// MLActive is whether an external anomaly model has written anything recently. Without it an
	// anomaly of 0 reads as "looks normal" when it means "nothing is scoring this".
	MLActive bool
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
	// What the address DID, as opposed to what was decided about it. An operator asking about an
	// attacker wants the second: how often, since when, against what, and which detections it tripped.
	if d.Events > 0 {
		fmt.Fprintf(&b, "Activity: %d event(s) on record", d.Events)
		if d.FirstSeen != "" {
			fmt.Fprintf(&b, ", first seen %s", d.FirstSeen)
		}
		if d.LastSeenEvent != "" {
			fmt.Fprintf(&b, ", last seen %s", d.LastSeenEvent)
		}
		b.WriteString(".\n")
		if len(d.Rules) > 0 {
			fmt.Fprintf(&b, "What it tripped: %s.\n", strings.Join(d.Rules, ", "))
		}
		if len(d.Agents) > 0 {
			fmt.Fprintf(&b, "Against: %s.\n", strings.Join(d.Agents, ", "))
		}
		if len(d.Countries) > 0 {
			fmt.Fprintf(&b, "Geolocated to: %s.\n", strings.Join(d.Countries, ", "))
		}
	}
	if d.HasCTI {
		fmt.Fprintf(&b, "Reputation: AbuseIPDB confidence %d/100, %d OTX pulse(s)", d.Abuse, d.OTX)
		if d.CTICountry != "" {
			fmt.Fprintf(&b, ", %s", d.CTICountry)
		}
		if d.CTISource != "" {
			fmt.Fprintf(&b, " (%s)", d.CTISource)
		}
		switch {
		case d.CTILive:
			b.WriteString(". Looked up just now, because nothing recent was cached.")
		case d.CTIAge != "":
			// Stated rather than hidden: a confidence of 0 from a month ago and one from this
			// morning are different claims, and reporting them identically is how an address that
			// has since turned bad stays clean in the telling.
			fmt.Fprintf(&b, ". Cached, last checked %s.", d.CTIAge)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("Reputation: no threat-intelligence record for this address, and none could be fetched. That is an absence of data, not a clean verdict; say it that way.\n")
	}
	if d.HasScore {
		fmt.Fprintf(&b, "Composite threat score: %d", d.Score)
		if d.Band != "" {
			fmt.Fprintf(&b, " (%s)", d.Band)
		}
		b.WriteString(". That is the scorer's own view, built from reputation, repeat offences, worst severity and cross-agent fan-out.")
		switch {
		case !d.MLActive:
			// The distinction that makes this worth carrying at all: the same zero means opposite
			// things depending on whether anything is running, and only one of them is reassuring.
			b.WriteString(" Its ML anomaly component reads 0 because no external anomaly model is feeding this deployment, NOT because the address looks normal. Do not present that as a clean verdict.")
		case d.Anomaly > 0:
			fmt.Fprintf(&b, " The ML anomaly model scores it %d out of 100.", d.Anomaly)
		default:
			b.WriteString(" The ML anomaly model scored it 0, and here that genuinely means it looks ordinary to the model.")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ThreatStats is the malware/process detection picture, flattened by the caller.
type ThreatStats struct {
	Read                  bool
	Malicious, Suspicious int
	RecentNames           []string
	WindowHours           int
}

// Threats renders process-level malware classification: the one piece of machine learning that runs
// inside DeusWatch rather than through the external anomaly bridge, and therefore the only one that
// has anything to say on a deployment that never wired a model up.
func Threats(s ThreatStats) string {
	if !s.Read {
		return "PROCESS THREATS: could not be read just now. Say so rather than reporting none.\n"
	}
	if s.Malicious == 0 && s.Suspicious == 0 {
		return fmt.Sprintf("PROCESS THREATS: nothing classified suspicious or malicious in the last %d hours.\n", s.WindowHours)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "PROCESS THREATS in the last %d hours: %d malicious, %d suspicious.", s.WindowHours, s.Malicious, s.Suspicious)
	if len(s.RecentNames) > 0 {
		fmt.Fprintf(&b, " Most recent: %s.", strings.Join(s.RecentNames, ", "))
	}
	b.WriteString(" A malicious classification outranks volume: one of these matters more than ten thousand failed logins, and it belongs in your first sentence. The reasons, YARA matches and hashes are not in your context; send them to the process threat view for those.\n")
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

// CarriedIPs returns addresses named earlier in the conversation but absent from the current
// message, so a follow-up stays about the same address.
//
// Without this the lookup only ever saw the message in front of it, and a conversation about one
// address died the moment the operator stopped retyping it. The failure was reported with the
// assistant asking "what is the status of the ban on 2.57.122.245?" and then, one turn later,
// claiming that address was unknown to the deployment: it had no dossier because that turn's
// message did not contain the digits. "and is it blocked?" failed the same way, as does any typo
// that lands on a different valid address.
//
// Turns are scanned newest first and the assistant's own turns count, which is deliberate: the
// address the assistant itself just asked about is exactly the one the next message is answering.
// It also means a hallucinated address can be carried, so the caller must look these up locally and
// NOT spend a live reputation call on them.
func CarriedIPs(turns []string, current string, max int) []string {
	if max <= 0 {
		return nil
	}
	skip := map[string]bool{}
	for _, ip := range MentionedIPs(current) {
		skip[ip] = true
	}
	out := make([]string, 0, max)
	for i := len(turns) - 1; i >= 0 && len(out) < max; i-- {
		for _, ip := range MentionedIPs(turns[i]) {
			if skip[ip] {
				continue
			}
			skip[ip] = true
			if out = append(out, ip); len(out) == max {
				break
			}
		}
	}
	return out
}

// CarriedNote heads the carried reports. The model has to be told why an address it was not just
// asked about is in front of it, or it volunteers the report unprompted.
const CarriedNote = "The reports below are for addresses discussed EARLIER in this conversation, carried forward so a follow-up question still has the data. Use them when the operator is plainly still talking about one of them. Do not bring them up unprompted.\n"

// UserLine is one account, flattened by the caller.
type UserLine struct {
	Username, Role string
	Disabled       bool
}

// Users renders the account roster.
//
// Only usernames and roles, and the closing sentence says so. That limit is not modesty: the users
// table also holds password hashes and TOTP secrets, which is why it is absent from the SQL
// allowlist entirely. Naming what the assistant does not have is what stops it filling the rest in,
// the same rule the rule digest and the roster follow.
func Users(users []UserLine, visible bool) string {
	if !visible {
		// Said explicitly rather than omitted. An absent block is a vacuum, and a vacuum is what
		// the model fills with invented accounts; a stated refusal is something it can repeat.
		return "ACCOUNTS: you have NOT been given the user list, because the operator asking does not hold the manage_users permission. If they ask who the users are, say exactly that and point them at an administrator. Do not guess names or roles.\n"
	}
	var b strings.Builder
	if len(users) == 0 {
		return "ACCOUNTS: the user list came back empty, which should not happen on a running deployment. Say so rather than inventing accounts.\n"
	}
	fmt.Fprintf(&b, "ACCOUNTS: %d, and this is the COMPLETE list.\n", len(users))
	for _, u := range users {
		fmt.Fprintf(&b, "- %s: %s", u.Username, orUnknown(u.Role))
		if u.Disabled {
			b.WriteString(" (disabled)")
		}
		b.WriteString("\n")
	}
	b.WriteString("You have usernames and roles only. No email, no last-login, no two-factor status, nothing about passwords, and you cannot query the users table. For anything else about an account, send them to the Users page.\n")
	return b.String()
}

// reSHA256 finds a file hash the operator pasted. Only SHA-256: it is what FIM records, what the
// reputation providers key on, and a 32-char MD5 would silently look up nothing.
var reSHA256 = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)

// MentionedHashes returns SHA-256 hashes named in a message, capped like the address lookup.
func MentionedHashes(msg string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 2)
	for _, m := range reSHA256.FindAllString(msg, -1) {
		h := strings.ToLower(m)
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
		if len(out) == 2 {
			break
		}
	}
	return out
}

// FileReport is one hash: where it has been seen here, and what the reputation providers say.
type FileReport struct {
	SHA256 string
	// Seen locally.
	Paths     []string // "path on agent (n versions)"
	LocalOnly bool     // recorded by FIM but no reputation available
	// Reputation.
	HasRep           bool
	Verdict          string // known_good | known_bad | unknown
	Source, Detail   string
	Age              string
	Live             bool
	ProvidersEnabled bool
}

// HashReport renders what is known about a file hash.
//
// The verdict wording is the whole job. "unknown" from VirusTotal means no engine has an opinion,
// which is not the same as safe, and a report that lets those blur is how an operator clears a file
// nobody has ever examined.
func HashReport(f FileReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "FILE HASH %s (the operator named this; this is everything known about it)\n", f.SHA256)

	if len(f.Paths) > 0 {
		fmt.Fprintf(&b, "Seen on this deployment at: %s.\n", strings.Join(f.Paths, ", "))
	} else {
		b.WriteString("No file-integrity snapshot on this deployment has this hash, so it is not a file DeusWatch is watching.\n")
	}

	switch {
	case !f.ProvidersEnabled:
		b.WriteString("Reputation: no file-hash reputation provider is configured, so nothing could be checked. Add VirusTotal, MalwareBazaar or CIRCL hashlookup under Integrations. Say this is unchecked, never that it is clean.\n")
	case !f.HasRep:
		b.WriteString("Reputation: the lookup returned nothing. Unchecked, not clean.\n")
	default:
		switch f.Verdict {
		case "known_bad":
			fmt.Fprintf(&b, "Reputation: KNOWN BAD per %s. %s This outranks everything else in the answer and belongs in your first sentence.\n", f.Source, f.Detail)
		case "known_good":
			fmt.Fprintf(&b, "Reputation: known good per %s. %s That means it matched a known-software set or no engine flagged it; it does not mean the file on disk is unmodified, which is what the FIM snapshot is for.\n", f.Source, f.Detail)
		default:
			fmt.Fprintf(&b, "Reputation: UNKNOWN to %s. %s No provider has an opinion on this hash, which is not the same as safe: an unknown file nobody has examined is the normal shape of something new.\n", f.Source, f.Detail)
		}
		if f.Live {
			b.WriteString("Looked up just now.\n")
		} else if f.Age != "" {
			fmt.Fprintf(&b, "Cached, last checked %s.\n", f.Age)
		}
	}
	return b.String()
}

// NeedsHashLookup reports whether the operator asked for a file to be checked, as opposed to merely
// pasting a hash in passing. A live reputation call costs an API quota, so it is asked for.
var hashWords = []string{
	"scan", "check", "cek", "periksa", "reputation", "reputasi", "virustotal", "vt ", "malware",
	"berbahaya", "dangerous", "aman", "safe", "hash", "file ini", "this file",
}

func NeedsHashLookup(msg string) bool {
	low := strings.ToLower(msg)
	for _, w := range hashWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}
