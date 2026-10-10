package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The executable hash is what reaches VirusTotal and what the manager stores, so the two things
// that must hold are: it is the real SHA-256 of the whole file, and an oversized file yields
// nothing rather than the digest of a prefix. The old code returned the MD5 of the first 32MB,
// which for a large binary is a hash belonging to no file at all: every lookup missed, and a miss
// reads exactly like a clean verdict.
func TestComputeFileHashIsWholeFileSHA256(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.bin")
	payload := []byte("deuswatch process snapshot hash check")
	if err := os.WriteFile(p, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := computeFileHash(p)
	if err != nil {
		t.Fatalf("computeFileHash: %v", err)
	}
	sum := sha256.Sum256(payload)
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("hash = %s, want %s", got, want)
	}

	// Over the cap: no hash at all, rather than one computed from a prefix.
	big := filepath.Join(dir, "big.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxHashBytes + 1); err != nil { // sparse, costs no disk
		f.Close()
		t.Skipf("cannot create a sparse file here: %v", err)
	}
	f.Close()
	if h, err := computeFileHash(big); err == nil || h != "" {
		t.Errorf("oversized file returned hash %q err %v, want empty + error", h, err)
	}
}

// The attack this cache has to survive. An attacker who overwrites a binary in place must not keep
// its old clean hash: the reputation lookup would then be performed on the file they replaced, and
// the trojan reads as CLEAN. Keyed by path alone, the stale entry never expired, so this was a
// detection bypass for the lifetime of the agent process rather than a stale optimisation.
func TestHashCacheInvalidatesWhenTheBinaryIsReplaced(t *testing.T) {
	ClearHashCache()
	t.Cleanup(ClearHashCache)

	p := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(p, []byte("the original, benign binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := getOrComputeHash(p)
	if clean == "" {
		t.Fatal("no hash for the original file")
	}
	if again := getOrComputeHash(p); again != clean {
		t.Errorf("an unchanged file should hash the same: %s vs %s", again, clean)
	}

	// Overwritten in place, same path. Different length, so the size check alone catches it.
	if err := os.WriteFile(p, []byte("trojan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := getOrComputeHash(p); got == clean {
		t.Fatal("the replaced binary still reports the original hash: a cached clean verdict for " +
			"an attacker-controlled file is a detection bypass, not a stale cache")
	}

	// And a replacement of IDENTICAL length, which the size check cannot see. mtime moves, so the
	// entry is still invalidated.
	before := getOrComputeHash(p)
	if err := os.WriteFile(p, []byte("TROJAN"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Skipf("cannot set mtime here: %v", err)
	}
	if got := getOrComputeHash(p); got == before {
		t.Error("a same-length replacement with a newer mtime must be re-hashed")
	}
}

// A Stat failure used to skip the size guard and fall through to hashing a 64MiB prefix, which is
// the truncated-digest bug the guard exists to prevent. Not directly reachable in a test, so the
// closed path is asserted through the cases that are: no hash is ever returned for a file the
// function could not fully account for.
func TestComputeFileHashFailsClosed(t *testing.T) {
	dir := t.TempDir()

	// A directory opens fine and stats fine, but is not a regular file.
	if h, err := computeFileHash(dir); err == nil || h != "" {
		t.Errorf("a directory returned %q err %v, want empty + error", h, err)
	}
	// A path that does not exist.
	if h, err := computeFileHash(filepath.Join(dir, "nope")); err == nil || h != "" {
		t.Errorf("a missing file returned %q err %v, want empty + error", h, err)
	}
}

// Memory is bounded on a host that runs short-lived processes from many distinct paths.
func TestHashCacheIsBounded(t *testing.T) {
	ClearHashCache()
	t.Cleanup(ClearHashCache)

	// The map is filled directly rather than through maxHashCache real files: what is under test
	// is the eviction, and writing four thousand files to assert it costs 20 seconds of I/O that
	// proves nothing extra.
	hashCacheMu.Lock()
	for i := 0; i < maxHashCache; i++ {
		hashCache[fmt.Sprintf("/synthetic/bin-%d", i)] = hashEntry{hash: "x", at: time.Now()}
	}
	hashCacheMu.Unlock()

	p := filepath.Join(t.TempDir(), "one-more")
	if err := os.WriteFile(p, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if getOrComputeHash(p) == "" {
		t.Fatal("a full cache must not stop a file being hashed")
	}
	if n := HashCacheSize(); n > maxHashCache {
		t.Errorf("cache holds %d entries, over the %d cap", n, maxHashCache)
	}
}
