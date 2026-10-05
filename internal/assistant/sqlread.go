package assistant

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Read-only database access for questions no pre-built block answers.
//
// The blocks in this package each closed one vacuum after an operator found it, and that does not
// scale: there is always another question. This is the general answer, and it is also the most
// dangerous thing in the package, so the controls are worth stating plainly.
//
//   - The model can only ever produce a SELECT. The query runs inside a READ ONLY transaction, so
//     Postgres itself refuses any write regardless of what this file's parser thinks. That is an
//     engine guarantee, not a promise from a regex, and it is the one that matters because a bug
//     in a parser is a full-access bug.
//   - Tables are ALLOWLISTED, not blocklisted. The database holds password hashes, encrypted
//     integration secrets and session tokens, and a blocklist is one forgotten table away from
//     leaking them. Anything not named below is refused even though it would read fine.
//   - Row-level security still applies, because the query runs in the caller's tenant scope. A
//     user cannot read another tenant's events through this any more than through the UI.
//   - Statement timeout and a row cap, so a question about "all events" cannot pin the database
//     the detection pipeline is writing to.
//
// The prompt that generates the SQL also contains text written by whoever is attacking this system.
// The allowlist is what makes that survivable: an injected "also select from users" is refused here,
// not argued with in the prompt.

// AllowedTables is every table the assistant may read.
//
// Chosen by asking "would it be acceptable for this to appear in a chat answer", which excludes
// users (password hashes), integrations (encrypted credentials), sessions and agent_enroll_tokens
// (live credentials), cti_config and notify_config (API keys). audit_log is excluded for a different
// reason: it is the record of who did what, and a question that needs it deserves a deliberate look
// at the real page rather than a summary a model wrote.
var AllowedTables = map[string]string{
	"events":                    "normalised log events; time, event_category, event_action, event_outcome, event_severity, dw_label (set = alert), dw_rule, dw_technique, source_ip, destination_ip, source_port, destination_port, user_name, host_name, file_path, process_name, process_command_line, agent_id, event_original",
	"response_actions":          "ban decisions; created_at, source_ip, action, reason, rule_id, ban_seconds, offense_count, source, status (recommended|approved|executed|dismissed|failed|unbanned), responder, agent_id, executed_at, decided_at",
	"agents":                    "enrolled endpoints; name, os, enrolled_at, last_seen_at, revoked, status, health_detail, agent_version, config_version, deleted_at",
	"rules":                     "detection rules; name, kind (single|aggregation), category, enabled, builtin, created_at, updated_at. The yaml column is large: do not select it unless asked for one rule",
	"tickets":                   "investigation tickets; title, description, severity (0-4), status (open|in_progress|resolved|closed), assignee, created_by, created_at, updated_at",
	"ticket_comments":           "comments on tickets; ticket_id, author, body, created_at",
	"playbooks":                 "response playbooks; name, tactic, enabled, yaml",
	"decoders":                  "custom log decoders; name, enabled",
	"ip_whitelist":              "addresses the response engine will never ban; cidr, note, kind, created_at",
	"ip_scores":                 "composite threat score per address; ip, score, band, fired_times, abuse, otx, max_sev, anomaly, updated_at",
	"ip_anomaly":                "ML anomaly score per address (0-100), written by an EXTERNAL model through the ML bridge; ip, anomaly, updated_at. Empty means no model is running, not that nothing is anomalous",
	"process_threats":           "malware classification per process; process_name, process_path, cmdline, file_hash, threat_level (CLEAN|SUSPICIOUS|MALICIOUS), reasons, yara_matches, behavioral_score, detected_at, agent_id",
	"process_snapshots":         "process listings reported by agents; agent_id, captured_at",
	"process_behavior_baseline": "expected characteristics per process name, the baseline malware classification compares against",
	"yara_rules":                "YARA rules used for file and process matching; name, enabled",
	"file_hash_reputation":      "file-hash reputation lookups; sha256, verdict, source, fetched_at",
	"suspicious_ips":            "low-and-slow reconnaissance watchlist; ip, reason, first_seen, last_seen",
	"slow_scanners":             "multi-day scanning behaviour; ip, days_seen, first_seen, last_seen",
	"agent_vulnerabilities":     "vulnerability findings per endpoint; agent_name, package, version, vuln_id, severity, cvss, fixed_version",
	"agent_sca_findings":        "dependency vulnerabilities from lockfiles; agent_name, manifest, package, version, vuln_id, severity",
	"agent_os_inventory":        "OS release per endpoint; agent_name, os_id, os_version, codename",
	"agent_packages":            "installed packages per endpoint; agent_name, name, version",
	"fim_snapshots":             "captured file versions; agent_name, path, sha256, size, captured_at, trigger",
	"containment_actions":       "host isolation actions; agent_name, status, requested_at, released_at",
	"service_heartbeats":        "component liveness; service, last_seen_at, version",
	"scan_status":               "vulnerability scan state per agent; agent_name, status, detail, updated_at",
	"cti_indicators":            "threat-intelligence lookups; indicator, source, score, fetched_at",
	"advisories":                "imported security advisories",
	"osv_vulns":                 "cached OSV vulnerability records; id, cve, severity, cvss",
	"workspaces":                "workspaces; name, created_at",
	"tenants":                   "tenants; name, created_at",
}

// MaxQueryRows caps a result. Enough to answer a question, far short of an export.
const MaxQueryRows = 50

// QueryTimeoutSeconds bounds one query. The detection pipeline is writing to this database.
const QueryTimeoutSeconds = 15

var (
	reFencedSQL = regexp.MustCompile("(?is)```(?:sql)?\\s*\\n(.*?)```")
	// Whatever follows FROM or JOIN, including a quoted identifier or an opening parenthesis.
	//
	// The quoted alternative is not decoration. Without it `from "users"` matched nothing at all,
	// the loop below had no identifier to check, and the query was allowed: an allowlist that
	// silently skips what it cannot parse is not an allowlist. Anything unrecognised is now
	// refused rather than skipped, so a syntax this does not understand fails closed.
	reFromJoin = regexp.MustCompile(`(?is)\b(?:from|join)\s+("[^"]*"|\(|[a-zA-Z_][a-zA-Z0-9_.$]*|\S+)`)
	// CTE names are not tables. They are collected so a readable query can use them, and the real
	// tables inside the CTE body are checked by the same pass.
	reCTE     = regexp.MustCompile(`(?is)(?:\bwith\s+(?:recursive\s+)?|,)\s*("[^"]*"|[a-zA-Z_][a-zA-Z0-9_$]*)\s+as\s*\(`)
	reComment = regexp.MustCompile(`(?s)/\*.*?\*/|--[^\n]*`)
)

// smallTalk are the messages that genuinely need no data, and they are the ONLY ones the schema
// guide is withheld from.
//
// The gate used to work the other way: list the phrasings that sound like a data question and
// attach the guide for those. That failed twice in production for the same reason, and the second
// failure is what prompted this. "the ips of SSH login attempts as root user today, name 5 of it"
// matched nothing, so the guide was absent, so no query could be written, so the assistant said it
// did not have the detail while sitting on a table that did.
//
// The mistake was enumerating the open set. There is no end to how a person can ask for data, and
// every miss looks to the operator like the feature not existing. Small talk is a closed set:
// greetings, thanks, and goodbyes, in two languages. Enumerating THAT is finishable.
//
// So the default is now "this probably needs data", and the failure mode flips from "cannot answer"
// to "a slightly longer prompt". On a slow local model that costs seconds; the old default cost the
// answer.
var smallTalk = []string{
	"hello", "hi", "hey", "yo", "good morning", "good afternoon", "good evening", "good night",
	"thanks", "thank you", "thx", "ok", "okay", "cool", "nice", "great", "bye", "see you",
	"halo", "hai", "pagi", "siang", "sore", "malam", "makasih", "terima kasih", "thx ya",
	"oke", "okee", "sip", "mantap", "dadah", "sampai jumpa", "selamat tinggal",
}

// NeedsQuery reports whether to spend the schema guide on this message.
//
// True unless the message is small talk, a command, or a memory instruction, each of which is
// answered without the model or without data. Everything else is assumed to want rows.
func NeedsQuery(msg string) bool {
	low := strings.ToLower(strings.TrimSpace(msg))
	low = strings.TrimRight(low, " .!?~")
	if low == "" {
		return false
	}
	// An exact match only. "hi" is small talk; "hi, which IPs hit us?" is not, and a substring
	// test would silently withhold the guide from the second.
	if slices.Contains(smallTalk, low) {
		return false
	}
	// A very short message with no question in it is chatter rather than a request for data.
	if len(low) < 12 && !strings.ContainsAny(low, "?") {
		for _, w := range smallTalk {
			if strings.HasPrefix(low, w) {
				return false
			}
		}
	}
	return true
}

// ExtractSQL pulls a statement out of a model reply.
func ExtractSQL(reply string) (string, bool) {
	if m := reFencedSQL.FindStringSubmatch(reply); m != nil {
		q := strings.TrimSpace(m[1])
		if q != "" {
			return q, true
		}
	}
	return "", false
}

// ValidateQuery decides whether a generated statement may run. The error is written for the
// operator, not the model: they see it in the panel when a query is refused.
func ValidateQuery(q string) error {
	clean := strings.TrimSpace(reComment.ReplaceAllString(q, " "))
	clean = strings.TrimSuffix(clean, ";")
	if clean == "" {
		return fmt.Errorf("the query was empty")
	}
	// One statement. Postgres would happily run "select 1; drop table x" as a batch.
	if strings.Contains(clean, ";") {
		return fmt.Errorf("only one statement is allowed")
	}
	lower := strings.ToLower(clean)
	if !strings.HasPrefix(lower, "select") && !strings.HasPrefix(lower, "with") {
		return fmt.Errorf("only SELECT is allowed, this started with %q", firstWord(clean))
	}
	// Catalogue access would enumerate the tables the allowlist exists to hide.
	for _, bad := range []string{"pg_", "information_schema", "current_setting", "set_config", "pg_sleep", "dblink", "copy "} {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("%q is not allowed in an assistant query", strings.TrimSpace(bad))
		}
	}
	// CTE names first, so a query may read from its own WITH clause. The tables inside each CTE
	// body are ordinary FROM targets and are checked below like any other.
	cte := map[string]bool{}
	for _, m := range reCTE.FindAllStringSubmatch(clean, -1) {
		cte[strings.ToLower(strings.Trim(m[1], `"`))] = true
	}

	for _, m := range reFromJoin.FindAllStringSubmatch(clean, -1) {
		raw := strings.TrimSpace(m[1])
		// A subquery or LATERAL has no name here; whatever it reads is matched on its own FROM.
		if raw == "(" || strings.EqualFold(raw, "lateral") {
			continue
		}
		name := strings.ToLower(strings.Trim(raw, `"`))
		if cte[name] {
			continue
		}
		if _, ok := AllowedTables[name]; !ok {
			return fmt.Errorf("table %q is not readable by the assistant (readable: %s)", name, allowedList())
		}
	}
	return nil
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " \t\n("); i > 0 {
		return s[:i]
	}
	return s
}

func allowedList() string {
	names := make([]string, 0, len(AllowedTables))
	for k := range AllowedTables {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// commonTables are the ones an operator actually asks about. They get their columns spelled out;
// everything else in AllowedTables is listed by name only.
//
// The split exists because the guide now travels with almost every message, and 25 described tables
// cost more prompt than the handful anybody queries. A name-only table is still readable: the model
// can guess ordinary column names, and a wrong guess produces a database error the operator sees,
// which is a far better failure than the table being invisible.
var commonTables = []string{"events", "response_actions", "agents", "rules", "tickets", "ip_scores"}

// SQLGuide is the schema the model writes against.
func SQLGuide() string {
	var b strings.Builder
	b.WriteString("QUERYING THE DATABASE\n")
	b.WriteString("When a question needs rows no block above contains, write ONE PostgreSQL SELECT in a fenced sql block and say in one sentence what it answers. The server runs it and shows the operator the rows. You will not see them: never invent a result.\n")
	fmt.Fprintf(&b, "One statement, SELECT only, always LIMIT %d or less, and only the tables below. Anything else is refused and the operator sees the refusal instead of an answer.\n", MaxQueryRows)
	b.WriteString("A result from an earlier query appears in the history as a [Query result] table. You MAY read and reason about those rows.\n")
	b.WriteString("Timestamps are timestamptz: use `time >= now() - interval '24 hours'`. IP columns are inet: compare with `source_ip = '1.2.3.4'::inet`, print with `host(source_ip)`. An alert is a row where `dw_label IS NOT NULL`. Name a rule with `COALESCE(rule_name, rule_id)`.\n")
	b.WriteString("Main tables:\n")
	for _, n := range commonTables {
		fmt.Fprintf(&b, "- %s: %s\n", n, AllowedTables[n])
	}
	rest := make([]string, 0, len(AllowedTables))
	for k := range AllowedTables {
		if !slices.Contains(commonTables, k) {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	fmt.Fprintf(&b, "Also readable, ask for columns if unsure: %s.\n", strings.Join(rest, ", "))
	b.WriteString("Not readable, and asking is refused: users, integrations, sessions, agent_enroll_tokens, cti_config, notify_config, audit_log. They hold credentials or belong on their own page. If a question needs one, say so and name the page.\n")
	return b.String()
}
