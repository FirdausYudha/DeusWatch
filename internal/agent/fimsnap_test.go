package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotEnsureAndRestore(t *testing.T) {
	snapDir := t.TempDir()
	webDir := t.TempDir()
	f := filepath.Join(webDir, "index.php")
	good := "<?php echo 'Welcome';\n"
	if err := os.WriteFile(f, []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := NewSnapshotStore(snapDir)
	if err != nil {
		t.Fatal(err)
	}

	// First sight: snapshot the good content.
	store.Ensure(f, good)
	if c, ok := store.Read(f); !ok || c != good {
		t.Fatalf("snapshot not stored: ok=%v c=%q", ok, c)
	}
	// Ensure must NOT overwrite an existing snapshot (defaced content must not replace good).
	store.Ensure(f, "<?php echo 'PWNED';")
	if c, _ := store.Read(f); c != good {
		t.Fatalf("Ensure overwrote the known-good snapshot: %q", c)
	}

	// Deface the file, then restore.
	if err := os.WriteFile(f, []byte("<?php system($_GET['c']); ?>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Restore(f); err != nil {
		t.Fatalf("restore: %v", err)
	}
	back, _ := os.ReadFile(f)
	if string(back) != good {
		t.Fatalf("file not restored to good content: %q", back)
	}

	// Restoring a path with no snapshot must error, not silently succeed.
	if err := store.Restore(filepath.Join(webDir, "nope.php")); err == nil {
		t.Fatal("restore without a snapshot must fail")
	}
}

func TestScannerPersistsSnapshot(t *testing.T) {
	snapDir := t.TempDir()
	webDir := t.TempDir()
	f := filepath.Join(webDir, "config.php")
	os.WriteFile(f, []byte("<?php $db='prod';\n"), 0o644)

	store, _ := NewSnapshotStore(snapDir)
	sc := NewFIMScanner(webDir).WithSnapshots(store)
	if _, err := sc.Scan(); err != nil { // baseline scan persists the snapshot
		t.Fatal(err)
	}
	if c, ok := store.Read(f); !ok || c == "" {
		t.Fatalf("scanner did not persist a snapshot for %s", f)
	}
}

func TestSnapshotStoreNilSafe(t *testing.T) {
	var s *SnapshotStore
	s.Ensure("/x", "y") // must not panic
	if _, ok := s.Read("/x"); ok {
		t.Fatal("nil store must read nothing")
	}
	if err := s.Restore("/x"); err == nil {
		t.Fatal("nil store restore must error")
	}
}
