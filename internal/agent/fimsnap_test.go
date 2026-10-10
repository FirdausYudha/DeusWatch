package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotSaveAndReadVersion(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Real digests, not placeholders. SaveVersion now refuses anything that is not 64 hex digits,
	// because the key becomes a path segment and used to reach one straight from a request body.
	// Production always passes hashBytes() output, so this is what the function actually receives.
	hashA := "f69f2c2353f91e70f6076e282185cdea553ec501da6600cc0714ab5587ac6bc1" // sha256("content-A")
	hashB := "b25005c47785cb934849e1d5408447e9a21e43cbacebb6899c5753569c702ba7" // sha256("content-B")

	// First save of a content hash → created.
	if created, err := store.SaveVersion(hashA, "content-A"); err != nil || !created {
		t.Fatalf("first SaveVersion: created=%v err=%v", created, err)
	}
	// Same hash again → de-duplicated (content-addressed).
	if created, err := store.SaveVersion(hashA, "content-A"); err != nil || created {
		t.Fatalf("dup SaveVersion should not re-create: created=%v err=%v", created, err)
	}
	// A different version coexists.
	if created, err := store.SaveVersion(hashB, "content-B"); err != nil || !created {
		t.Fatalf("second version: created=%v err=%v", created, err)
	}
	// Both versions are independently readable.
	if c, ok := store.ReadVersion(hashA); !ok || c != "content-A" {
		t.Fatalf("ReadVersion hashA = %q, %v", c, ok)
	}
	if c, ok := store.ReadVersion(hashB); !ok || c != "content-B" {
		t.Fatalf("ReadVersion hashB = %q, %v", c, ok)
	}
	if _, ok := store.ReadVersion("7aafadc6ffdcb4b210bd9bc3799d94801adf5a8a99befbb1db8d016ce38825dd"); ok {
		t.Fatal("ReadVersion of a missing hash should be ok=false")
	}
	// nil store is safe.
	var nilStore *SnapshotStore
	if created, _ := nilStore.SaveVersion(hashA, "y"); created {
		t.Fatal("nil store SaveVersion must be a no-op")
	}
}

func TestRestoreVersion(t *testing.T) {
	store, err := NewSnapshotStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "conf.txt")
	if err := os.WriteFile(target, []byte("CURRENT (bad) content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Save a historical good version, then restore the file to it by hash.
	good := "GOOD historical content\n"
	sum := hashBytes([]byte(good))
	if _, err := store.SaveVersion(sum, good); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreVersion(target, sum); err != nil {
		t.Fatalf("RestoreVersion: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != good {
		t.Fatalf("file not restored: got %q want %q", got, good)
	}
	// Restoring an unknown version errors (content not on this agent).
	if err := store.RestoreVersion(target, "deadbeef"); err == nil {
		t.Fatal("restoring an unknown version should error")
	}
}

func TestSnapshotModeHelpers(t *testing.T) {
	cases := []struct {
		mode            string
		onChange, sched bool
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

// The blob key becomes a path segment, and it arrives from an HTTP request body:
// POST /api/fim/restore-version {agent, path, sha256} -> a queued action -> this agent -> a file
// written to disk. Both the API and the store only checked len(sha) == 64, which a traversal
// string satisfies just as well as a digest does.
func TestBlobKeyRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSnapshotStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	good := strings.Repeat("ab", 32) // 64 hex characters
	if _, ok := s.blobPath(good); !ok {
		t.Fatalf("a real sha256 must be accepted: %s", good)
	}

	// Exactly 64 characters, and it escapes the blobs directory.
	escape := strings.Repeat("../", 17) + "///etc/shadow"
	if len(escape) != 64 {
		t.Fatalf("the test case must be 64 chars to prove the length check is not enough, got %d", len(escape))
	}
	if _, ok := s.blobPath(escape); ok {
		t.Error("a 64-character traversal was accepted: the length check was never the defence")
	}

	for _, bad := range []string{
		"", "short",
		strings.Repeat("a", 63), strings.Repeat("a", 65),
		strings.Repeat("a", 63) + "/",                              // separator
		strings.Repeat("a", 63) + ".",                              // dot
		strings.Repeat("a", 63) + "g",                              // not hex
		strings.Repeat("a", 32) + "\x00" + strings.Repeat("a", 31), // NUL
	} {
		if _, ok := s.blobPath(bad); ok {
			t.Errorf("accepted %q as a blob key", bad)
		}
	}

	// And the functions that use it fail closed rather than reading some other file.
	if _, ok := s.ReadVersion(escape); ok {
		t.Error("ReadVersion followed a traversal key")
	}
	if _, err := s.SaveVersion(escape, "payload"); err == nil {
		t.Error("SaveVersion wrote under a traversal key")
	}
}
