//go:build cgo
// +build cgo

package yara

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScannerLoadAndMatch is the end-to-end guarantee that manager-side YARA scanning does what the
// gateway snapshot handler needs: compile from a directory, scan bytes, return the matched rule's
// name + namespace + description meta. Runs only under CGO builds; skipped on the nocgo stub.
func TestScannerLoadAndMatch(t *testing.T) {
	dir := t.TempDir()
	rule := `rule TestEicar
{
    meta:
        description = "EICAR test string"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}`
	if err := os.WriteFile(filepath.Join(dir, "eicar.yar"), []byte(rule), 0o644); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	s := New()
	defer s.Close()
	n, err := s.LoadFromDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n != 1 || !s.HasRules() {
		t.Fatalf("expected 1 loaded ruleset with rules, got n=%d hasRules=%v", n, s.HasRules())
	}

	eicar := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	matches, err := s.Scan(eicar)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	m := matches[0]
	if m.Rule != "TestEicar" {
		t.Errorf("rule name: got %q, want TestEicar", m.Rule)
	}
	if m.Namespace != "eicar" {
		t.Errorf("namespace: got %q, want eicar (file basename)", m.Namespace)
	}
	if m.Description != "EICAR test string" {
		t.Errorf("description: got %q, want the meta value", m.Description)
	}

	// A benign buffer must not fire.
	if hits, _ := s.Scan([]byte("hello world")); len(hits) != 0 {
		t.Errorf("benign content triggered %d match(es): %+v", len(hits), hits)
	}
}

// TestScannerEmptyDirIsSilent guards the "fresh install with no rules" boot path: an empty or
// missing rules directory must not error — the scanner is simply idle.
func TestScannerEmptyDirIsSilent(t *testing.T) {
	s := New()
	defer s.Close()
	n, err := s.LoadFromDir(t.TempDir())
	if err != nil || n != 0 || s.HasRules() {
		t.Fatalf("empty dir must be silent: n=%d err=%v hasRules=%v", n, err, s.HasRules())
	}
	n, err = s.LoadFromDir("/definitely/does/not/exist")
	if err != nil || n != 0 {
		t.Fatalf("missing dir must be silent: n=%d err=%v", n, err)
	}
	// Scan on empty scanner is a no-op, never errors.
	if m, err := s.Scan([]byte("anything")); err != nil || m != nil {
		t.Fatalf("scan on empty scanner must no-op: matches=%v err=%v", m, err)
	}
}
