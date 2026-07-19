package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineForAnalysis(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "quarantine")
	victim := filepath.Join(tmp, "suspect.conf")
	const content = "OLD-OR-SUSPECT FILE CONTENT preserved for analysis\n"
	if err := os.WriteFile(victim, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	dest, err := QuarantineForAnalysis(victim, qdir)
	if err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	// Original is moved out of place (neutralized).
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("original file should be gone after quarantine")
	}
	// The evidence copy exists, read-only, with the content preserved.
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("quarantined file missing: %v", err)
	}
	if fi.Mode().Perm()&0o200 != 0 { // must be read-only (inert evidence); Windows maps 0400→0444
		t.Fatalf("quarantined file should not be writable, got %o", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(dest)
	if string(b) != content {
		t.Fatalf("quarantined content not preserved: %q", b)
	}
	// Missing file → error (nothing to quarantine).
	if _, err := QuarantineForAnalysis(filepath.Join(tmp, "nope"), qdir); err == nil {
		t.Fatal("quarantine of a missing file should error")
	}
}

func TestRemediateFile(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "q")

	write := func(name, content string) string {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// quarantine: matching hash -> moved out of place, original gone.
	bad := write("evil.sh", "malware")
	h, err := fileSHA256(bad)
	if err != nil {
		t.Fatal(err)
	}
	acted, err := RemediateFile(bad, h, "quarantine", qdir)
	if err != nil || !acted {
		t.Fatalf("quarantine should act: acted=%v err=%v", acted, err)
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("original file should be gone after quarantine")
	}
	entries, _ := os.ReadDir(qdir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 quarantined file, got %d", len(entries))
	}

	// hash mismatch -> never touched.
	keep := write("keep.sh", "clean")
	acted, err = RemediateFile(keep, "0000000000000000000000000000000000000000000000000000000000000000", "delete", qdir)
	if err != nil || acted {
		t.Fatalf("mismatched hash must be a no-op: acted=%v err=%v", acted, err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("a hash-mismatched file must not be touched")
	}

	// delete: matching hash -> removed.
	del := write("drop.bin", "evil2")
	dh, _ := fileSHA256(del)
	acted, err = RemediateFile(del, dh, "delete", qdir)
	if err != nil || !acted {
		t.Fatalf("delete should act: acted=%v err=%v", acted, err)
	}
	if _, err := os.Stat(del); !os.IsNotExist(err) {
		t.Fatal("file should be deleted")
	}

	// missing file -> safe no-op.
	if acted, err := RemediateFile(filepath.Join(tmp, "nope"), dh, "delete", qdir); err != nil || acted {
		t.Fatalf("missing file must be a no-op: acted=%v err=%v", acted, err)
	}
}
