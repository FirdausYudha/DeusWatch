// Package sigma adalah PROTOTIPE SPIKE evaluator Sigma untuk DeusWatch.
//
// Tujuannya membuktikan kelayakan & memahami biaya: parse rule Sigma, cocokkan
// terhadap event DCS, ekstrak tag MITRE. Ini SUBSET sengaja (lihat docs/adr/
// 0001-sigma-detection-engine.md) — bukan implementasi Sigma penuh. Korelasi/
// agregasi (mis. brute-force "count() > N") TIDAK didukung di sini dan diarahkan
// ke jalur SQL (model Zircolite/pySigma).
//
// Didukung: selection berupa map field->nilai/daftar; modifier contains/
// startswith/endswith/re; kondisi and/or/not + tanda kurung + "N of them" /
// "all of <prefix>*". Tidak didukung: selection list/keywords, pipa agregasi.
package sigma

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"deuswatch/internal/ingest"
)

// Rule adalah rule Sigma yang sudah di-parse (subset).
type Rule struct {
	ID        string
	Title     string
	Level     string
	Tags      []string
	LogSource map[string]string

	condition  string
	selections map[string]selection
}

type selection struct {
	fields []fieldCond
}

type fieldCond struct {
	name      string
	modifiers []string
	values    []string // dicocokkan secara OR
}

// ParseRule mem-parse satu rule Sigma dari YAML.
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
		return nil, fmt.Errorf("sigma: detection.condition wajib ada")
	}
	cond, ok := condRaw.(string)
	if !ok {
		return nil, fmt.Errorf("sigma: condition berupa daftar belum didukung (subset)")
	}
	if strings.Contains(cond, "|") {
		return nil, fmt.Errorf("sigma: kondisi agregasi (|) tidak didukung di sini — gunakan jalur SQL")
	}

	r := &Rule{
		ID: raw.ID, Title: raw.Title, Level: raw.Level, Tags: raw.Tags,
		LogSource: raw.LogSource, condition: cond, selections: map[string]selection{},
	}
	for name, v := range raw.Detection {
		if name == "condition" {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("sigma: selection %q bukan map (list/keywords belum didukung)", name)
		}
		var sel selection
		for fk, fv := range m {
			parts := strings.Split(fk, "|")
			sel.fields = append(sel.fields, fieldCond{
				name: parts[0], modifiers: parts[1:], values: toStringSlice(fv),
			})
		}
		r.selections[name] = sel
	}
	return r, nil
}

// Matches mengevaluasi rule terhadap event yang sudah diratakan (ECS dotted keys).
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

// MITRE mengekstrak technique ID & nama tactic dari tag (attack.tXXXX / attack.<tactic>).
func (r *Rule) MITRE() (techniqueID, tactic string) {
	for _, t := range r.Tags {
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

// Severity memetakan level Sigma ke ingest.Severity DCS.
func (r *Rule) Severity() ingest.Severity {
	switch strings.ToLower(r.Level) {
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

// ── pencocokan selection ──────────────────────────────────

func (s selection) match(event map[string]any) bool {
	for _, fc := range s.fields { // semua field harus cocok (AND)
		if !fc.match(event) {
			return false
		}
	}
	return len(s.fields) > 0
}

func (fc fieldCond) match(event map[string]any) bool {
	raw, ok := event[fc.name]
	if !ok {
		return false
	}
	got := toStr(raw)
	for _, exp := range fc.values { // daftar nilai = OR
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
		return false // modifier di luar subset
	}
}

// ── parser kondisi (subset) ───────────────────────────────

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
		return false, fmt.Errorf("sigma: token kondisi tersisa: %v", p.toks[p.pos:])
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
			return false, fmt.Errorf("sigma: tanda kurung tutup hilang")
		}
		return v, nil
	case t == "all" || t == "any" || isNumber(t):
		if p.take() != "of" {
			return false, fmt.Errorf("sigma: harap 'of' setelah %q", t)
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
		return false, fmt.Errorf("sigma: kondisi tidak lengkap")
	default:
		v, ok := p.sel[t]
		if !ok {
			return false, fmt.Errorf("sigma: selection tak dikenal: %q", t)
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

// ── util ──────────────────────────────────────────────────

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
