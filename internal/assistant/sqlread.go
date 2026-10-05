package assistant

import (
	"fmt"
	"regexp"
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

var sqlWords = []string{
	"query the database", "run a query", "sql", "select from", "how many rows",
	"list all", "show me all", "count how many", "group by",
	"query database", "jalankan query", "berapa banyak", "tampilkan semua", "daftar semua",
	"hitung berapa", "cari di database", "query ke database",
}

// NeedsQuery reports whether the question is worth spending the schema guide on. Deliberately
// narrow: the guide is large, the model is slow, and most questions are answered by the blocks
// already in the prompt without a round trip through SQL.
func NeedsQuery(msg string) bool {
	low := strings.ToLower(msg)
	for _, w := range sqlWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
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

// SQLGuide is the schema the model writes against.
func SQLGuide() string {
	var b strings.Builder
	b.WriteString("QUERYING THE DATABASE\n")
	b.WriteString("When a question needs data no block above contains, you may write ONE PostgreSQL SELECT and the server will run it and show the operator the rows. Put it in a fenced sql block and say in one sentence what it answers. Do not invent the result: you will not see the rows, the operator will.\n")
	fmt.Fprintf(&b, "Rules: one statement, SELECT only, always add LIMIT %d or less, and read only the tables listed here. Anything else is refused and the operator sees the refusal instead of an answer.\n", MaxQueryRows)
	b.WriteString("Timestamps are `timestamptz`; use `now() - interval '24 hours'` style bounds. IP columns are `inet`: compare with `source_ip = '1.2.3.4'::inet` and print with `host(source_ip)`.\n")
	b.WriteString("Readable tables and their useful columns:\n")
	names := make([]string, 0, len(AllowedTables))
	for k := range AllowedTables {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "- %s: %s\n", n, AllowedTables[n])
	}
	b.WriteString("Not readable, and asking for them is refused: users, integrations, sessions, agent_enroll_tokens, cti_config, notify_config, audit_log. They hold credentials or belong on their own page. If a question needs one, say so and name the page instead.\n")
	return b.String()
}
