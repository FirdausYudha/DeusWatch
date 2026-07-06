package sigma

import (
	"fmt"
	"os"
	"path/filepath"
)

// Ruleset is a collection of parsed Sigma rules.
type Ruleset []*Rule

// Rule kinds (evaluation path).
const (
	KindSingle      = "single"
	KindAggregation = "aggregation"
)

// Classify validates a Sigma rule's YAML and reports whether it is a single-event or an
// aggregation rule. Returns an error if it is not a valid rule of either kind — used by
// the DB rule store to reject bad input and pick the right evaluation path.
func Classify(data []byte) (kind string, err error) {
	if isAggregation(data) {
		if _, err := ParseAggRule(data); err != nil {
			return "", err
		}
		return KindAggregation, nil
	}
	if _, err := ParseRule(data); err != nil {
		return "", err
	}
	return KindSingle, nil
}

// ruleFiles gathers *.yml / *.yaml paths in dir (recursive one level). A directory
// that does not exist yields an empty list (not an error).
func ruleFiles(dir string) ([]string, error) {
	var files []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
		sub, err := filepath.Glob(filepath.Join(dir, "*", pat))
		if err != nil {
			return nil, err
		}
		files = append(files, sub...)
	}
	return files, nil
}

// LoadDir loads SINGLE-EVENT Sigma rules from dir (recursive one level) as a Ruleset.
// Files with an aggregation condition ('|') are skipped here — load them via
// LoadAggDir. A directory that does not exist yields an empty Ruleset (not an error).
func LoadDir(dir string) (Ruleset, error) {
	files, err := ruleFiles(dir)
	if err != nil {
		return nil, err
	}
	var rs Ruleset
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("sigma: read %s: %w", f, err)
		}
		if isAggregation(data) {
			continue // aggregation rule → SQL path (LoadAggDir)
		}
		r, err := ParseRule(data)
		if err != nil {
			return nil, fmt.Errorf("sigma: parse %s: %w", f, err)
		}
		rs = append(rs, r)
	}
	return rs, nil
}

// LoadAggDir loads AGGREGATION Sigma rules from dir (recursive one level). Single-event
// files are skipped. A directory that does not exist → an empty list (not an error).
func LoadAggDir(dir string) ([]*AggRule, error) {
	files, err := ruleFiles(dir)
	if err != nil {
		return nil, err
	}
	var out []*AggRule
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("sigma: read %s: %w", f, err)
		}
		if !isAggregation(data) {
			continue
		}
		r, err := ParseAggRule(data)
		if err != nil {
			return nil, fmt.Errorf("sigma: parse aggregation %s: %w", f, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// Match returns the rules that match the event (the event is already flattened).
// A rule is only evaluated when the event is in scope for its logsource (AppliesTo), so a
// web/judi/deface rule never runs on an sshd/FIM/firewall line and a FIM rule never runs on
// a web line - each rule stays on its real source.
func (rs Ruleset) Match(event map[string]any) []*Rule {
	var hits []*Rule
	for _, r := range rs {
		if !r.AppliesTo(event) {
			continue
		}
		if ok, err := r.Matches(event); err == nil && ok {
			hits = append(hits, r)
		}
	}
	return hits
}
