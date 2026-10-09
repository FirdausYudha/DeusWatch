package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
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
