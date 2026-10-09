package assistant

import (
	"regexp"
	"strings"
)

// Sigma rule drafting (ADR 0003, phase 5).
//
// This is the first capability where the MODEL produces the content of a change rather than being
// kept out of the action path. Ban and whitelist are parsed from the operator's own sentence
// precisely so a model cannot originate them; a rule cannot work that way, because writing the rule
// is the task. Three things carry the weight instead:
//
//   - The draft is validated with the real engine (sigma.Classify) before any card appears, so a
//     rule that cannot parse never reaches the operator as something to approve.
//   - The operator reviews the YAML itself, never a summary. They are approving code.
//   - Saving goes through the ordinary POST /api/rules under their own session, so manage_rules is
//     enforced by the endpoint that already enforces it.
//
// A rule can only ADD detection; nothing here can disable an existing one. The realistic damage
// from a bad draft is noise, which is why human review of the actual text is enough.

var ruleWords = []string{
	"sigma", "rule for", "a rule", "new rule", "write a rule", "create a rule", "detection rule",
	"buat rule", "bikin rule", "buat aturan", "bikin aturan", "buatkan rule", "rule baru",
	"deteksi", "detect ",
	// More ways to ask for a rule, including the signature/alert vocabulary and Indonesian phrasings.
	"rule untuk", "rule buat", "aturan deteksi", "buatkan aturan", "alert for", "alert untuk", "signature",
}

// NeedsRuleAuthoring reports whether the message is asking for a rule to be written. Like the other
// gates in this package it is a plain keyword test: the authoring guide is large, and spending it
// on every message would crowd the prompt for no benefit.
func NeedsRuleAuthoring(msg string) bool {
	low := strings.ToLower(msg)
	for _, w := range ruleWords {
		if strings.Contains(low, w) {
			return true
		}
	}
	return false
}

// MaxRuleYAML caps a drafted rule. Generous for a Sigma rule and far short of a keyword list long
// enough to slow the matcher down on every event.
const MaxRuleYAML = 8000

// reFenced pulls the YAML out of a fenced block. Models wrap code even when told not to, and asking
// for bare YAML then failing on the backticks would be a brittle way to lose a good draft.
var reFenced = regexp.MustCompile("(?s)```(?:ya?ml)?\\s*\\n(.*?)```")

// ExtractRuleYAML returns the rule text from a model reply, and whether anything was found. The
// caller must still validate it with the engine: this only locates the candidate.
func ExtractRuleYAML(reply string) (string, bool) {
	if m := reFenced.FindStringSubmatch(reply); m != nil {
		y := strings.TrimSpace(m[1])
		if y != "" && len(y) <= MaxRuleYAML {
			return y, true
		}
		return "", false
	}
	// Unfenced but clearly a rule: every rule in this engine needs both of these keys.
	t := strings.TrimSpace(reply)
	if strings.Contains(t, "title:") && strings.Contains(t, "detection:") && len(t) <= MaxRuleYAML {
		return t, true
	}
	return "", false
}

// RuleAuthoringGuide describes the Sigma subset this engine actually implements.
//
// Generic Sigma knowledge is not enough and is actively harmful here: a model drafting from memory
// reaches for pipes, near-correlation and field names this evaluator has never supported, and the
// rule is rejected on save with a parse error the operator cannot act on. The field list is the
// flattened event the matcher sees, the categories are the ones the logsource mapping knows, and
// the two examples are shaped like the rules already in the repository.
const RuleAuthoringGuide = `HOW TO DRAFT A SIGMA RULE FOR THIS ENGINE
DeusWatch implements a SUBSET of Sigma. Do not use syntax from memory that is not listed here; a rule using anything else is rejected when saved.

Reply with the rule as a single fenced yaml block and at most two sentences before it explaining what it catches. No commentary inside the YAML beyond normal comments.

Required keys: title, id (any unique uuid-like string), status, description, level, logsource, detection, tags.
level: informational | low | medium | high | critical
tags: MITRE technique ids as attack.tXXXX, plus the tactic as attack.<tactic>.

logsource.category, and the event kind it scopes the rule to:
  web (HTTP access logs) | authentication (sshd, windows logons) | file_event (FIM) | process_creation | network_connection | firewall | dns
A rule with no logsource runs against EVERY event. Always set one unless that is genuinely intended.

Fields you may match on, exactly these names:
  event.dataset, event.category, event.action, event.outcome, event.severity, event.original
  source.ip, source.port, destination.ip, destination.port
  user.name, user.domain, host.name, host.os.type
  process.name, process.command_line, process.pid, file.path
event.original is the raw log line. A keywords selection always matches against event.original only.

detection: either a named map of field -> value (a list of values means OR), or a "keywords" list of strings that are substring-matched case-insensitively against the raw line.
Modifiers on a field: |contains, |startswith, |endswith, |re (Go regexp).
condition: and / or / not, parentheses, "N of them", "all of <prefix>*".

SINGLE-EVENT EXAMPLE
title: Webshell upload attempt
id: 7c1f2a90-3b44-4a01-9c2e-5d6a8f0b1234
status: experimental
description: >
  A request writing a script file into a web-served directory, the common first step of a webshell.
level: high
logsource:
  category: web
detection:
  selection:
    http.uri|contains:
      - '.php'
      - '.jsp'
    event.action: upload
  condition: selection
tags:
  - attack.t1505.003
  - attack.persistence

AGGREGATION (counting) EXAMPLE. Use this shape when the rule is "N of something within a window", which runs on the SQL path instead:
title: SSH brute force
id: 1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: >
  Many SSH failures from one source IP in a short window.
level: high
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event.dataset: sshd
    event.outcome: failure
  timeframe: 5m
  condition: selection | count() by source.ip > 20
tags:
  - attack.t1110
  - attack.credential_access

Only count() is supported in the pipe, grouped by one field.

NOT SUPPORTED, do not emit: any pipe other than count(), near/correlation rules, fieldrefs, placeholders, base64 or utf16 modifiers, regex features beyond Go's regexp.

Keep keyword lists short and specific. A keyword that is an ordinary word matches ordinary traffic: it will fire all day on legitimate pages and teach the operator to ignore the rule.`

var reTitle = regexp.MustCompile(`(?m)^title:\s*(.+)$`)

// RuleTitle pulls the title out of a drafted rule for the confirmation card's heading. The rules
// store derives the same thing on save; this is only so the card is not blank before then.
func RuleTitle(yaml string) string {
	if m := reTitle.FindStringSubmatch(yaml); m != nil {
		return strings.TrimSpace(strings.Trim(m[1], `"'`))
	}
	return "Untitled rule"
}
