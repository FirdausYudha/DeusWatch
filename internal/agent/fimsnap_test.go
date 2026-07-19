package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotSaveAndReadVersion(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// First save of a content hash → created.
	if created, err := store.SaveVersion("hashA", "content-A"); err != nil || !created {
		t.Fatalf("first SaveVersion: created=%v err=%v", created, err)
	}
	// Same hash again → de-duplicated (content-addressed).
	if created, err := store.SaveVersion("hashA", "content-A"); err != nil || created {
		t.Fatalf("dup SaveVersion should not re-create: created=%v err=%v", created, err)
	}
	// A different version coexists.
	if created, err := store.SaveVersion("hashB", "content-B"); err != nil || !created {
		t.Fatalf("second version: created=%v err=%v", created, err)
	}
	// Both versions are independently readable.
	if c, ok := store.ReadVersion("hashA"); !ok || c != "content-A" {
		t.Fatalf("ReadVersion hashA = %q, %v", c, ok)
	}
	if c, ok := store.ReadVersion("hashB"); !ok || c != "content-B" {
		t.Fatalf("ReadVersion hashB = %q, %v", c, ok)
	}
	if _, ok := store.ReadVersion("missing"); ok {
		t.Fatal("ReadVersion of a missing hash should be ok=false")
	}
	// nil store is safe.
	var nilStore *SnapshotStore
	if created, _ := nilStore.SaveVersion("x", "y"); created {
		t.Fatal("nil store SaveVersion must be a no-op")
	}
}

func TestSnapshotModeHelpers(t *testing.T) {
	cases := []struct {
		mode              string
		onChange, sched   bool
	}{
		{"", false, false},
		{"baseline", false, false},
		{"on_change", true, false},
		{"scheduled", false, true},
		{"both", true, true},
	}
	for _, c := range cases {
		s := Source{SnapshotMode: c.mode}
		if s.snapshotOnChange() != c.onChange || s.snapshotScheduled() != c.sched {
			t.Fatalf("mode %q: onChange=%v scheduled=%v, want %v/%v", c.mode, s.snapshotOnChange(), s.snapshotScheduled(), c.onChange, c.sched)
		}
	}
}

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
