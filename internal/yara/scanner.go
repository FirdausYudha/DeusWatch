//go:build cgo
// +build cgo

// Package yara wraps libyara for content scanning at ingest time (used by the gateway's FIM
// snapshot handler). This file is the real, libyara-backed implementation; a no-op stub lives in
// scanner_nocgo.go for `CGO_ENABLED=0` builds so `go build ./...` on a dev box without libyara
// still succeeds.
//
// Design in one line: manager-side scanning of file bytes that arrive with FIM snapshot uploads;
// matches surface as an alert event that flows through the normal enrichment/response pipeline.
package yara

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	yara "github.com/Velocidex/go-yara"
)

// Match is one YARA rule that fired on a scanned buffer. Rule is the identifier, Namespace groups
// rules by filename (one .yar file = one namespace) so an operator can tell which ruleset fired,
// and Description is the `description` meta field if the rule sets one (falls back to "").
type Match struct {
	Rule        string `json:"rule"`
	Namespace   string `json:"namespace"`
	Description string `json:"description"`
}

// Scanner compiles .yar files from a directory and scans byte buffers against them. Safe for
// concurrent Scan calls; LoadFromDir swaps the compiled rules atomically so an in-flight scan
// keeps using the rules it started with.
type Scanner struct {
	mu       sync.RWMutex
	rules    *yara.Rules
	loadedAt time.Time
	loaded   int
}

// New returns an empty scanner. Call LoadFromDir before Scan.
func New() *Scanner { return &Scanner{} }

// LoadFromDir compiles every *.yar / *.yara file in dir (non-recursive) into one ruleset, one
// namespace per file (the file's base name without extension). An empty dir is not an error — the
// scanner is simply idle until rules appear, mirroring the "no CTI provider configured" behaviour
// of the enricher. Returns the number of files consumed. On a parse error the previous ruleset is
// kept in place, so a bad rule doesn't take the scanner down mid-flight.
func (s *Scanner) LoadFromDir(dir string) (int, error) {
	files, err := listRuleFiles(dir)
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.rules, s.loaded, s.loadedAt = nil, 0, time.Now()
		return 0, nil
	}

	compiler, err := yara.NewCompiler()
	if err != nil {
		return 0, fmt.Errorf("yara: compiler: %w", err)
	}
	// The compiler holds file handles until GetRules(); Close() releases them.
	defer compiler.Close()

	for _, f := range files {
		content, rerr := os.ReadFile(f)
		if rerr != nil {
			return 0, fmt.Errorf("yara: read %s: %w", f, rerr)
		}
		ns := ruleNamespace(f)
		if aerr := compiler.AddString(string(content), ns); aerr != nil {
			return 0, fmt.Errorf("yara: compile %s: %w", filepath.Base(f), aerr)
		}
	}

	rules, cerr := compiler.GetRules()
	if cerr != nil {
		return 0, fmt.Errorf("yara: get rules: %w", cerr)
	}

	s.mu.Lock()
	old := s.rules
	s.rules = rules
	s.loaded = len(files)
	s.loadedAt = time.Now()
	s.mu.Unlock()
	// Free the old ruleset AFTER the swap so any in-flight scan finishes first.
	if old != nil {
		old.Close()
	}
	return len(files), nil
}

// Scan returns every rule that fired against data. Nil rules or empty data → nil match (no-op),
// never an error. A scan has a hard 10s ceiling so a pathological rule can't stall the ingest
// path. Zero copy: yara scans the caller's byte slice in place.
func (s *Scanner) Scan(data []byte) ([]Match, error) {
	s.mu.RLock()
	rules := s.rules
	s.mu.RUnlock()
	if rules == nil || len(data) == 0 {
		return nil, nil
	}
	var out []Match
	cb := func(rule *yara.Rule, matched bool) (proceed bool) {
		if !matched {
			return true
		}
		out = append(out, Match{
			Rule:        rule.Identifier(),
			Namespace:   rule.Namespace(),
			Description: metaDescription(rule),
		})
		return true
	}
	if err := rules.ScanMem(data, yara.ScanFlags(0), 10*time.Second, cb); err != nil {
		return nil, fmt.Errorf("yara: scan: %w", err)
	}
	// Deterministic order so identical content yields identical detail strings across runs.
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out, nil
}

// HasRules reports whether the scanner has any compiled rules — the gateway uses this to decide
// whether YARA is effectively enabled (vs configured with an empty rules dir).
func (s *Scanner) HasRules() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rules != nil
}

// Loaded returns the number of .yar files last successfully compiled + when — used by the boot
// log so the operator sees "yara: loaded N rulesets from …" at startup.
func (s *Scanner) Loaded() (int, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loaded, s.loadedAt
}

// Close releases the compiled ruleset.
func (s *Scanner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rules != nil {
		s.rules.Close()
		s.rules = nil
	}
	return nil
}

// listRuleFiles returns absolute paths to every *.yar / *.yara in dir, sorted so compilation is
// deterministic (the rule namespace derives from the filename — deterministic order = deterministic
// namespaces). Missing dir is not an error; it's treated as "no rules".
func listRuleFiles(dir string) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("yara: read dir %s: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yar" && ext != ".yara" {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	sort.Strings(files)
	return files, nil
}

func ruleNamespace(path string) string {
	base := filepath.Base(path)
	return base[:len(base)-len(filepath.Ext(base))]
}

func metaDescription(r *yara.Rule) string {
	for _, m := range r.Metas() {
		if m.Identifier == "description" {
			if s, ok := m.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}
