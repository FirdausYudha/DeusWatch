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
		// Phrasings the original gate missed, which is what made the assistant feel like it did not
		// understand the request: the capability was there, the keyword was not.
		"gimana cara nyambungin crowdsec ke DW?",
		"konek mikrotik dong",
		"integrasikan slack",
		"settingan smtp di mana?",
		"daftarkan webhook baru",
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

// The point of the reachability probe: the assistant can now answer "is nftables connected?" with
// a verified yes/no instead of restating what is enabled in config. Each probe outcome must render
// as the state it is, and the dangerous ones (not live, probe failed) must carry the same
// "FLAGGED, not blocked" warning the not-configured case does.
func TestEnforcementReachabilityProbe(t *testing.T) {
	base := EnforcementStats{Read: true, ActiveCount: 1, ActiveBlocks: []string{"1.2.3.4"}}

	// Live and the probe passed: a ban genuinely reaches the firewall.
	ok := base
	ok.Probed, ok.EdgeBackend, ok.EdgeLive, ok.EdgeChecked, ok.EdgeReachable = true, "nftables", true, true, true
	if g := Enforcement(ok); !strings.Contains(g, "nftables passed its last reachability check") || strings.Contains(g, "FLAGGED, not blocked") {
		t.Errorf("a reachable backend must read as working, not flagged:\n%s", g)
	}

	// Configured but RESPONSE_LIVE is off: recorded, not pushed.
	dry := base
	dry.Probed, dry.EdgeBackend, dry.EdgeLive = true, "nftables", false
	if g := Enforcement(dry); !strings.Contains(g, "RESPONSE_LIVE is off") || !strings.Contains(g, "FLAGGED, not blocked") {
		t.Errorf("a dry-run backend must warn it is not blocking:\n%s", g)
	}

	// Live but the probe FAILED: the most dangerous state - looks set up, bans are not landing.
	fail := base
	fail.Probed, fail.EdgeBackend, fail.EdgeLive, fail.EdgeChecked, fail.EdgeReachable = true, "nftables", true, true, false
	fail.EdgeDetail = "nftables set 'inet deuswatch banlist' is not usable"
	g := Enforcement(fail)
	if !strings.Contains(g, "reachability check FAILED") || !strings.Contains(g, "FLAGGED, not blocked") || !strings.Contains(g, "not usable") {
		t.Errorf("a failed probe must warn and carry the reason:\n%s", g)
	}

	// Probed, but nothing is configured to push bans.
	none := base
	none.Probed = true
	if g := Enforcement(none); !strings.Contains(g, "enforcement is NOT configured") {
		t.Errorf("no backend must read as not configured:\n%s", g)
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

// The bug this closes: "is 72.167.227.34 dangerous?" was answered "I don't see any information
// about that IP" while it sat in the first row of the Response page with four offences. Dozens of
// addresses were tied on the same count, so the one asked about fell outside the top-N slice.
func TestMentionedIPs(t *testing.T) {
	got := MentionedIPs("is 72.167.227.34 dangerous? and what about 2001:db8::1 ?")
	if len(got) != 2 || got[0] != "72.167.227.34" || got[1] != "2001:db8::1" {
		t.Errorf("got %v", got)
	}
	// A CIDR is a range to whitelist, not an address with a history to look up.
	if g := MentionedIPs("whitelist 10.0.0.0/8"); len(g) != 0 {
		t.Errorf("a CIDR should not be looked up, got %v", g)
	}
	// A pasted log excerpt must not become twenty queries.
	many := "1.1.1.1 2.2.2.2 3.3.3.3 4.4.4.4 5.5.5.5"
	if g := MentionedIPs(many); len(g) != 3 {
		t.Errorf("expected the cap of 3, got %v", g)
	}
	// Version strings are not addresses; the same boundary rule as the ban parser applies.
	if g := MentionedIPs("agent version 1.2.3.4.5.6"); len(g) != 0 {
		t.Errorf("a version fragment is not an address, got %v", g)
	}
}

func TestIPReportDistinguishesTheStates(t *testing.T) {
	banned := IPReport(Dossier{IP: "72.167.227.34", Found: true, Offenses: 4, Total: 6, Pending: 2,
		LastReason: "SSH Login Attempt for Invalid User", LastAgent: "test-server", Events24h: 310})
	for _, want := range []string{
		"6 total decision(s), 4 executed ban(s), 2 waiting",
		"SSH Login Attempt for Invalid User",
		// Banned before and banned now are different, and the operator usually means now.
		"No ban is in force right now, even though it has been banned before",
		"310 event(s) in the last 24 hours, so it is active right now",
	} {
		if !strings.Contains(banned, want) {
			t.Errorf("report missing %q:\n%s", want, banned)
		}
	}

	// "Never seen" is a real answer and must be given plainly, not hedged into uselessness.
	unknown := IPReport(Dossier{IP: "8.8.8.8"})
	if !strings.Contains(unknown, "genuinely unknown to this deployment") {
		t.Errorf("an unknown address needs a definite answer:\n%s", unknown)
	}

	// A whitelisted address cannot be banned, and saying so saves a pointless confirmation card.
	wl := IPReport(Dossier{IP: "10.0.0.5", Found: true, Total: 1, Listed: true})
	if !strings.Contains(wl, "on the WHITELIST") {
		t.Errorf("whitelist membership must be stated:\n%s", wl)
	}
}

func TestUsersRosterStatesItsCeiling(t *testing.T) {
	g := Users([]UserLine{
		{Username: "admin", Role: "admin"},
		{Username: "viewer1", Role: "viewer", Disabled: true},
	}, true)
	for _, want := range []string{
		"2, and this is the COMPLETE list",
		"admin: admin",
		"viewer1: viewer (disabled)",
		// Naming what it does not have is what stops it filling the rest in.
		"usernames and roles only",
		"nothing about passwords",
		"cannot query the users table",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("roster missing %q:\n%s", want, g)
		}
	}
	// A password hash or TOTP secret must never appear in the rendered block, whatever is passed.
	for _, leak := range []string{"hash", "totp", "secret", "password_hash"} {
		if strings.Contains(strings.ToLower(g), leak) && !strings.Contains(g, "nothing about passwords") {
			t.Errorf("roster mentions %q:\n%s", leak, g)
		}
	}
}

// Without manage_users the block must REFUSE out loud rather than be absent: an omitted block is
// the vacuum that gets filled with invented accounts, which is how this whole class of bug works.
func TestUsersRosterRefusesWithoutPermission(t *testing.T) {
	g := Users(nil, false)
	for _, want := range []string{"NOT been given the user list", "manage_users", "Do not guess names or roles"} {
		if !strings.Contains(g, want) {
			t.Errorf("refusal missing %q:\n%s", want, g)
		}
	}
	if strings.Contains(g, "COMPLETE list") {
		t.Errorf("a refusal must not look like a roster:\n%s", g)
	}
}

// An empty result on a running deployment is a fault, not an answer, and must read as one.
func TestUsersRosterEmptyIsSuspicious(t *testing.T) {
	g := Users(nil, true)
	if !strings.Contains(g, "should not happen") {
		t.Errorf("an empty roster should be flagged rather than reported as fact:\n%s", g)
	}
}

// The distinction this block exists for: an anomaly of 0 means "looks ordinary" only when a model
// is actually running. With no model it means nothing was scored, and presenting that as a clean
// verdict is the silent kind of wrong.
func TestIPReportSeparatesNoModelFromNoAnomaly(t *testing.T) {
	noModel := IPReport(Dossier{IP: "1.2.3.4", Found: true, HasScore: true, Score: 72, Band: "high", MLActive: false})
	if !strings.Contains(noModel, "no external anomaly model is feeding this deployment") ||
		!strings.Contains(noModel, "NOT because the address looks normal") {
		t.Errorf("a missing model must not read as a clean verdict:\n%s", noModel)
	}
	if !strings.Contains(noModel, "Composite threat score: 72 (high)") {
		t.Errorf("the composite score is the most direct answer to \"is it dangerous\":\n%s", noModel)
	}

	scoredZero := IPReport(Dossier{IP: "1.2.3.4", Found: true, HasScore: true, Score: 5, MLActive: true, Anomaly: 0})
	if !strings.Contains(scoredZero, "genuinely means it looks ordinary") {
		t.Errorf("with a model running, zero is a real verdict:\n%s", scoredZero)
	}
	scored := IPReport(Dossier{IP: "1.2.3.4", Found: true, HasScore: true, Score: 90, MLActive: true, Anomaly: 83})
	if !strings.Contains(scored, "scores it 83 out of 100") {
		t.Errorf("a real anomaly score should be reported:\n%s", scored)
	}
}

func TestThreatsLeadsWithMalicious(t *testing.T) {
	g := Threats(ThreatStats{Read: true, Malicious: 1, Suspicious: 3,
		RecentNames: []string{"xmrig (malicious)"}, WindowHours: 24})
	for _, want := range []string{"1 malicious, 3 suspicious", "xmrig (malicious)",
		"outranks volume", "belongs in your first sentence"} {
		if !strings.Contains(g, want) {
			t.Errorf("threat block missing %q:\n%s", want, g)
		}
	}
	// Nothing found and nothing readable are different answers, as everywhere else.
	if q := Threats(ThreatStats{Read: true, WindowHours: 24}); !strings.Contains(q, "nothing classified suspicious or malicious") {
		t.Errorf("a clean window should say so:\n%s", q)
	}
	if b := Threats(ThreatStats{Read: false}); !strings.Contains(b, "could not be read") {
		t.Errorf("an unreadable section must not read as clean:\n%s", b)
	}
}

// The ML tables must be queryable, or "what does the anomaly model say" has no answer at all.
func TestMLTablesAreReadable(t *testing.T) {
	for _, tbl := range []string{"ip_anomaly", "ip_scores", "process_threats", "process_behavior_baseline", "yara_rules"} {
		if _, ok := AllowedTables[tbl]; !ok {
			t.Errorf("%q should be readable by the assistant", tbl)
		}
	}
	// And the one that explains an empty result, so the model does not read silence as safety.
	if !strings.Contains(AllowedTables["ip_anomaly"], "Empty means no model is running") {
		t.Error("ip_anomaly's description must explain what empty means")
	}
}

// The report the operator asked for: reputation, how often, when it started and stopped, whether it
// is blocked, and what it tripped. Each in one place rather than spread across four pages.
func TestIPReportIsComplete(t *testing.T) {
	g := IPReport(Dossier{
		IP: "45.134.26.9", Found: true, Blocked: true, BlockedUntil: "2026-10-12 09:00 UTC",
		Offenses: 4, Total: 6, Pending: 1, LastReason: "Failed SSH Login as root",
		HasScore: true, Score: 88, Band: "high", MLActive: false,
		Events: 4912, FirstSeen: "2026-09-30 04:50 UTC", LastSeenEvent: "2026-10-05 21:14 UTC",
		Rules:  []string{"SSH Brute Force (3100)", "SSH Invalid User (812)"},
		Agents: []string{"test-server (4912)"}, Countries: []string{"VN (4912)"},
		HasCTI: true, Abuse: 100, OTX: 7, CTICountry: "VN", CTISource: "abuseipdb,otx", CTIAge: "3 hour(s) ago",
	})
	for _, want := range []string{
		"4 executed ban(s)",                   // how many times acted on
		"A ban is currently in force",         // blocked or not
		"4912 event(s) on record",             // how often it attacked
		"first seen 2026-09-30 04:50 UTC",     // when it started
		"last seen 2026-10-05 21:14 UTC",      // when it stopped
		"SSH Brute Force (3100)",              // what its offences were
		"AbuseIPDB confidence 100/100, 7 OTX", // its reputation
		"Cached, last checked 3 hour(s) ago",  // and how old that figure is
		"Composite threat score: 88 (high)",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("report missing %q:\n%s", want, g)
		}
	}
}

// No reputation data is an absence, not a verdict. Letting those blur is how an address nobody has
// ever checked gets described as clean.
func TestIPReportAbsentReputationIsNotClean(t *testing.T) {
	g := IPReport(Dossier{IP: "1.2.3.4", Found: true, Total: 1})
	if !strings.Contains(g, "absence of data, not a clean verdict") {
		t.Errorf("missing CTI must not read as a clean verdict:\n%s", g)
	}
	live := IPReport(Dossier{IP: "1.2.3.4", Found: true, Total: 1, HasCTI: true, Abuse: 90, CTILive: true})
	if !strings.Contains(live, "Looked up just now") {
		t.Errorf("a live lookup should say so:\n%s", live)
	}
}

func TestHashReportSeparatesUnknownFromSafe(t *testing.T) {
	unknown := HashReport(FileReport{SHA256: strings.Repeat("a", 64), ProvidersEnabled: true,
		HasRep: true, Verdict: "unknown", Source: "virustotal", Detail: "0/70 engines flagged"})
	if !strings.Contains(unknown, "not the same as safe") {
		t.Errorf("unknown must not read as safe:\n%s", unknown)
	}
	bad := HashReport(FileReport{SHA256: strings.Repeat("b", 64), ProvidersEnabled: true,
		HasRep: true, Verdict: "known_bad", Source: "virustotal", Detail: "48/70 engines flagged"})
	if !strings.Contains(bad, "KNOWN BAD") || !strings.Contains(bad, "first sentence") {
		t.Errorf("a known-bad hash must lead the answer:\n%s", bad)
	}
	none := HashReport(FileReport{SHA256: strings.Repeat("c", 64)})
	if !strings.Contains(none, "unchecked, never that it is clean") {
		t.Errorf("no provider configured must not read as clean:\n%s", none)
	}
	good := HashReport(FileReport{SHA256: strings.Repeat("d", 64), ProvidersEnabled: true,
		HasRep: true, Verdict: "known_good", Source: "circl", Detail: "NSRL known-good"})
	// Known-good is about the hash, not about the file currently on disk.
	if !strings.Contains(good, "does not mean the file on disk is unmodified") {
		t.Errorf("known-good needs its caveat:\n%s", good)
	}
}

func TestMentionedHashesAndGate(t *testing.T) {
	h := strings.Repeat("a1b2c3d4", 8) // 64 chars
	if got := MentionedHashes("cek hash " + h + " dong"); len(got) != 1 || got[0] != strings.ToLower(h) {
		t.Errorf("got %v", got)
	}
	// An MD5 is not looked up: the providers key on SHA-256 and a short hash would find nothing.
	if got := MentionedHashes("d41d8cd98f00b204e9800998ecf8427e"); len(got) != 0 {
		t.Errorf("an MD5 should not be looked up, got %v", got)
	}
	if !NeedsHashLookup("cek file ini berbahaya ngga?") || !NeedsHashLookup("scan this hash") {
		t.Error("an explicit check should trigger the lookup")
	}
	// File-analysis phrasings the original list missed. These only ever spend quota when a hash is
	// actually present, so being generous here is safe.
	for _, m := range []string{"tolong analisa file ini", "analyze this md5", "is this ransomware?"} {
		if !NeedsHashLookup(m) {
			t.Errorf("%q should trigger a file lookup", m)
		}
	}
	if NeedsHashLookup("what happened today?") {
		t.Error("an ordinary question should not spend an API quota")
	}
}

// The reported failure: the assistant asked about an address, the operator answered without
// retyping it in full, and the lookup had nothing because it only ever saw the current message.
func TestCarriedIPs(t *testing.T) {
	turns := []string{
		"is 2.57.122.245 dangerous?",
		"What's the status of the ban on 2.57.122.245?",
	}
	got := CarriedIPs(turns, "status is executed", 2)
	if len(got) != 1 || got[0] != "2.57.122.245" {
		t.Fatalf("expected the address from the earlier turn, got %v", got)
	}

	// A typo that lands on a different valid address still carries the original forward, which is
	// the whole point: the operator meant the one under discussion.
	if got := CarriedIPs(turns, "2.57.122.24 status is executed", 2); len(got) != 1 || got[0] != "2.57.122.245" {
		t.Errorf("a near-miss typo should not drop the subject, got %v", got)
	}

	// An address already in the message is not repeated as a carried report.
	if got := CarriedIPs(turns, "and 2.57.122.245 now?", 2); len(got) != 0 {
		t.Errorf("already present, should not be carried: %v", got)
	}

	// Newest first, and capped.
	many := []string{"1.1.1.1 here", "2.2.2.2 and 3.3.3.3", "4.4.4.4 last"}
	got = CarriedIPs(many, "what about it", 2)
	if len(got) != 2 || got[0] != "4.4.4.4" {
		t.Errorf("expected the two most recent, newest first, got %v", got)
	}
	if n := CarriedIPs(many, "", 0); len(n) != 0 {
		t.Errorf("max 0 should carry nothing, got %v", n)
	}
}
