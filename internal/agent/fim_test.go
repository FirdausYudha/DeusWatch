package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func findChange(changes []FIMChange, path string) (FIMChange, bool) {
	for _, c := range changes {
		if c.Path == path {
			return c, true
		}
	}
	return FIMChange{}, false
}

func TestFIMScannerBaselineThenDiff(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.conf")
	b := filepath.Join(dir, "b.conf")
	writeFile(t, a, "alpha")
	writeFile(t, b, "bravo")

	s := NewFIMScanner(dir)

	// First scan = baseline, no changes.
	changes, err := s.Scan()
	if err != nil {
		t.Fatalf("baseline scan: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("baseline must be 0 changes, got %d: %+v", len(changes), changes)
	}

	// Modify a, delete b, create c.
	writeFile(t, a, "alpha-changed")
	if err := os.Remove(b); err != nil {
		t.Fatalf("delete b: %v", err)
	}
	c := filepath.Join(dir, "c.conf")
	writeFile(t, c, "charlie")

	changes, err = s.Scan()
	if err != nil {
		t.Fatalf("scan diff: %v", err)
	}
	if len(changes) != 3 {
		t.Fatalf("expected 3 changes, got %d: %+v", len(changes), changes)
	}
	if ch, ok := findChange(changes, a); !ok || ch.Action != "modified" || ch.SHA256 == "" {
		t.Fatalf("a must be modified with a hash: %+v", ch)
	}
	if ch, ok := findChange(changes, b); !ok || ch.Action != "deleted" {
		t.Fatalf("b must be deleted: %+v", ch)
	}
	if ch, ok := findChange(changes, c); !ok || ch.Action != "created" {
		t.Fatalf("c must be created: %+v", ch)
	}

	// No further changes.
	changes, _ = s.Scan()
	if len(changes) != 0 {
		t.Fatalf("a stable scan must be 0 changes, got %d", len(changes))
	}
}

func TestFIMScannerSingleFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "watched.txt")
	writeFile(t, f, "v1")

	s := NewFIMScanner(f)
	if _, err := s.Scan(); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	writeFile(t, f, "v2")
	changes, _ := s.Scan()
	if len(changes) != 1 || changes[0].Action != "modified" {
		t.Fatalf("expected 1 modified, got %+v", changes)
	}
}

func TestSplitFIMPaths(t *testing.T) {
	got := splitFIMPaths(" /etc/passwd , /etc/ssh/sshd_config ,, ")
	if len(got) != 2 || got[0] != "/etc/passwd" || got[1] != "/etc/ssh/sshd_config" {
		t.Fatalf("wrong split: %+v", got)
	}
}
