// Package sigma is a SPIKE PROTOTYPE Sigma evaluator for DeusWatch.
//
// Its purpose is to prove feasibility & understand the cost: parse a Sigma rule, match
// against DCS events, extract MITRE tags. This is a deliberate SUBSET (see docs/adr/
// 0001-sigma-detection-engine.md) — not a full Sigma implementation. Correlation/
// aggregation (e.g. brute-force "count() > N") is NOT supported here and is routed
// to the SQL path (Zircolite/pySigma model).
//
// Supported: a selection map field->value/list; a keyword selection (a list of strings
// substring-matched against the event); the contains/startswith/endswith/re modifiers;
// and/or/not conditions + parentheses + "N of them" / "all of <prefix>*"; field aliases
// via the taxonomy (see mapping.go). Not supported: the aggregation pipe (SQL path).
package sigma

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"deuswatch/internal/ingest"
)

// Rule is a parsed Sigma rule (subset).
type Rule struct {
	ID        string
	Title     string
	Level     string
	Tags      []string
	LogSource map[string]string

	condition  string
	selections map[string]selection
}

// selection is either a map field->value (fields) OR a list of keywords (keywords)
// substring-matched against the event content (e.g. event.original).
type selection struct {
	fields   []fieldCond
	keywords []string
}

type fieldCond struct {
	name      string
	modifiers []string
	values    []string // matched as OR
}

// ParseRule parses a single Sigma rule from YAML.
func ParseRule(data []byte) (*Rule, error) {
	var raw struct {
		ID        string            `yaml:"id"`
		Title     string            `yaml:"title"`
		Level     string            `yaml:"level"`
		Tags      []string          `yaml:"tags"`
		LogSource map[string]string `yaml:"logsource"`
		Detection map[string]any    `yaml:"detection"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("sigma: parse YAML: %w", err)
	}

	condRaw, ok := raw.Detection["condition"]
	if !ok {
		return nil, fmt.Errorf("sigma: detection.condition is required")
	}
	cond, ok := condRaw.(string)
	if !ok {
		return nil, fmt.Errorf("sigma: a list-form condition is not supported yet (subset)")
	}
	if strings.Contains(cond, "|") {
		return nil, fmt.Errorf("sigma: aggregation condition (|) is not supported here — use the SQL path")
	}

	sels, err := parseSelections(raw.Detection)
	if err != nil {
		return nil, err
	}
	return &Rule{
		ID: raw.ID, Title: raw.Title, Level: raw.Level, Tags: raw.Tags,
		LogSource: raw.LogSource, condition: cond, selections: sels,
	}, nil
}

// parseSelections turns the detection block (except "condition"/"timeframe") into a
// name->selection map. Used by ParseRule and ParseAggRule.
func parseSelections(detection map[string]any) (map[string]selection, error) {
	out := map[string]selection{}
	for name, v := range detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		switch val := v.(type) {
		case map[string]any: // field->value selection
			var sel selection
			for fk, fv := range val {
				parts := strings.Split(fk, "|")
				sel.fields = append(sel.fields, fieldCond{
					name: parts[0], modifiers: parts[1:], values: toStringSlice(fv),
				})
			}
			out[name] = sel
		case []any: // keyword selection (substring match in the event)
			out[name] = selection{keywords: toStringSlice(val)}
		default:
			return nil, fmt.Errorf("sigma: selection %q not supported (not a map/keywords)", name)
		}
	}
	return out, nil
}

// Matches evaluates the rule against an already-flattened event (dotted ECS keys).
func (r *Rule) Matches(event map[string]any) (bool, error) {
	results := make(map[string]bool, len(r.selections))
	for name, sel := range r.selections {
		results[name] = sel.match(event)
	}
	return (&condParser{toks: tokenize(r.condition), sel: results, names: r.selectionNames()}).eval()
}

func (r *Rule) selectionNames() []string {
	names := make([]string, 0, len(r.selections))
	for n := range r.selections {
		names = append(names, n)
	}
	return names
}

// MITRE extracts the technique ID & tactic name from tags (attack.tXXXX / attack.<tactic>).
func (r *Rule) MITRE() (techniqueID, tactic string) { return mitreFromTags(r.Tags) }

// Severity maps the Sigma level to a DCS ingest.Severity.
func (r *Rule) Severity() ingest.Severity { return severityFromLevel(r.Level) }

// mitreFromTags & severityFromLevel are shared by Rule (single-event) and AggRule
// (aggregation) — see aggregate.go.
func mitreFromTags(tags []string) (techniqueID, tactic string) {
	for _, t := range tags {
		low := strings.ToLower(t)
		if !strings.HasPrefix(low, "attack.") {
			continue
		}
		val := strings.TrimPrefix(low, "attack.")
		if len(val) > 1 && val[0] == 't' && val[1] >= '0' && val[1] <= '9' {
			if techniqueID == "" {
				techniqueID = strings.ToUpper(val)
			}
			continue
		}
		if tactic == "" {
			tactic = titleCase(strings.ReplaceAll(val, "_", " "))
		}
	}
	return techniqueID, tactic
}

func severityFromLevel(level string) ingest.Severity {
	switch strings.ToLower(level) {
	case "critical":
		return ingest.SeverityCritical
	case "high":
		return ingest.SeverityHigh
	case "medium":
		return ingest.SeverityMedium
	case "low":
		return ingest.SeverityLow
	default:
		return ingest.SeverityInfo
	}
}

// ── selection matching ────────────────────────────────────

func (s selection) match(event map[string]any) bool {
	if len(s.keywords) > 0 {
		return matchKeywords(s.keywords, event)
	}
	for _, fc := range s.fields { // all fields must match (AND)
		if !fc.match(event) {
			return false
		}
	}
	return len(s.fields) > 0
}

// matchKeywords matches if any keyword appears (substring, case-insensitive) in the
// joined string values of the event (mainly event.original = the raw log line).
func matchKeywords(keywords []string, event map[string]any) bool {
	hay := haystack(event)
	for _, kw := range keywords {
		if strings.Contains(hay, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func haystack(event map[string]any) string {
	var b strings.Builder
	for _, v := range event {
		if s, ok := v.(string); ok {
			b.WriteString(strings.ToLower(s))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func (fc fieldCond) match(event map[string]any) bool {
	raw, ok := event[fc.name]
	if !ok { // try the taxonomy alias (e.g. "User" -> "user.name")
		raw, ok = event[resolveField(fc.name)]
	}
	if !ok {
		return false
	}
	got := toStr(raw)
	for _, exp := range fc.values { // value list = OR
		if matchValue(got, fc.modifiers, exp) {
			return true
		}
	}
	return false
}

func matchValue(got string, modifiers []string, expected string) bool {
	g, e := strings.ToLower(got), strings.ToLower(expected)
	if len(modifiers) == 0 {
		return g == e
	}
	switch modifiers[0] {
	case "contains":
		return strings.Contains(g, e)
	case "startswith":
		return strings.HasPrefix(g, e)
	case "endswith":
		return strings.HasSuffix(g, e)
	case "re":
		re, err := regexp.Compile(expected)
		return err == nil && re.MatchString(got)
	default:
		return false // modifier outside the subset
	}
}

// ── condition parser (subset) ─────────────────────────────

type condParser struct {
	toks  []string
	pos   int
	sel   map[string]bool
	names []string
}

func tokenize(cond string) []string {
	cond = strings.ReplaceAll(cond, "(", " ( ")
	cond = strings.ReplaceAll(cond, ")", " ) ")
	return strings.Fields(cond)
}

func (p *condParser) eval() (bool, error) {
	v, err := p.parseOr()
	if err != nil {
		return false, err
	}
	if p.pos != len(p.toks) {
		return false, fmt.Errorf("sigma: leftover condition tokens: %v", p.toks[p.pos:])
	}
	return v, nil
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) take() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *condParser) parseOr() (bool, error) {
	v, err := p.parseAnd()
	if err != nil {
		return false, err
	}
	for p.peek() == "or" {
		p.take()
		rhs, err := p.parseAnd()
		if err != nil {
			return false, err
		}
		v = v || rhs
	}
	return v, nil
}

func (p *condParser) parseAnd() (bool, error) {
	v, err := p.parseUnary()
	if err != nil {
		return false, err
	}
	for p.peek() == "and" {
		p.take()
		rhs, err := p.parseUnary()
		if err != nil {
			return false, err
		}
		v = v && rhs
	}
	return v, nil
}

func (p *condParser) parseUnary() (bool, error) {
	if p.peek() == "not" {
		p.take()
		v, err := p.parseUnary()
		return !v, err
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (bool, error) {
	t := p.take()
	switch {
	case t == "(":
		v, err := p.parseOr()
		if err != nil {
			return false, err
		}
		if p.take() != ")" {
			return false, fmt.Errorf("sigma: missing closing parenthesis")
		}
		return v, nil
	case t == "all" || t == "any" || isNumber(t):
		if p.take() != "of" {
			return false, fmt.Errorf("sigma: expected 'of' after %q", t)
		}
		target := p.take()
		names := p.resolveTargets(target)
		matched := 0
		for _, n := range names {
			if p.sel[n] {
				matched++
			}
		}
		if t == "all" {
			return len(names) > 0 && matched == len(names), nil
		}
		need := 1
		if isNumber(t) {
			need, _ = strconv.Atoi(t)
		}
		return matched >= need, nil
	case t == "":
		return false, fmt.Errorf("sigma: incomplete condition")
	default:
		v, ok := p.sel[t]
		if !ok {
			return false, fmt.Errorf("sigma: unknown selection: %q", t)
		}
		return v, nil
	}
}

func (p *condParser) resolveTargets(target string) []string {
	if target == "them" {
		return p.names
	}
	if strings.HasSuffix(target, "*") {
		prefix := strings.TrimSuffix(target, "*")
		var out []string
		for _, n := range p.names {
			if strings.HasPrefix(n, prefix) {
				out = append(out, n)
			}
		}
		return out
	}
	return []string{target}
}

// ── utils ─────────────────────────────────────────────────

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func toStringSlice(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, toStr(e))
		}
		return out
	default:
		return []string{toStr(v)}
	}
}

func toStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func titleCase(s string) string {
	parts := strings.Fields(s)
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}
