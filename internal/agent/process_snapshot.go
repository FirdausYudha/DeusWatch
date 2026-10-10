package agent

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// ProcessSnapshot captures the state of one running process at a point in time.
// These snapshots are shipped to the manager for malware analysis.
type ProcessSnapshot struct {
	PID       int       `json:"pid"`
	Name      string    `json:"name"` // e.g. "svchost.exe", "chrome"
	ParentPID int       `json:"parent_pid"`
	Cmdline   string    `json:"cmdline"`
	User      string    `json:"user"` // owner of process (UID on Linux, username on Windows)
	Path      string    `json:"path"` // full path to executable
	StartTime time.Time `json:"start_time"`
	MemoryMB  uint64    `json:"memory_mb"`
	FileHash  string    `json:"file_hash"` // SHA-256 of executable, "" when unavailable
}

// ProcessSnapshotBatch is a collection of process snapshots from one agent at a point in time.
type ProcessSnapshotBatch struct {
	Timestamp time.Time         `json:"timestamp"`
	Processes []ProcessSnapshot `json:"processes"`
}

// The hash cache exists because a snapshot runs every few minutes and most executables on a box
// never change between two of them. Re-reading every binary each time is real I/O on a production
// host.
//
// It is keyed by path AND identity, which is the whole point. Keyed by path alone it was a
// detection bypass rather than an optimisation: an attacker who overwrites /usr/bin/something in
// place keeps its old clean SHA-256 shipped for the lifetime of the agent process, and every
// reputation lookup is then performed on a hash that belongs to the file the attacker replaced.
// Replacing a binary in place is not an exotic attack, it is the ordinary one this agent exists to
// catch.
type hashEntry struct {
	hash    string
	size    int64
	modTime time.Time
	at      time.Time
}

const (
	// hashCacheTTL bounds how stale an entry can be even when size and mtime are unchanged. Those
	// two are forgeable: `touch -r` copies a timestamp, and a replacement of identical length keeps
	// the size. The TTL turns an indefinite bypass into a bounded one.
	hashCacheTTL = 30 * time.Minute
	// maxHashCache bounds memory on a host that runs short-lived processes from many distinct
	// paths, where the map would otherwise grow for the life of the agent.
	// ponytail: clear-all when full, not an LRU. One path per executable means this is reached
	// rarely; swap for an LRU if a profile ever shows the re-hash cost after a clear.
	maxHashCache = 4096
)

var (
	hashCacheMu sync.RWMutex
	hashCache   = make(map[string]hashEntry)
)

// getOrComputeHash returns the SHA-256 of a file, reusing a cached value only while the file still
// looks like the one that was hashed.
func getOrComputeHash(path string) string {
	// Stat before the cache lookup: the cache is only valid against the file as it is NOW, so
	// there is nothing to check a cached entry against without it.
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}

	hashCacheMu.RLock()
	e, ok := hashCache[path]
	hashCacheMu.RUnlock()
	if ok && e.size == fi.Size() && e.modTime.Equal(fi.ModTime()) && time.Since(e.at) < hashCacheTTL {
		return e.hash
	}

	hash, err := computeFileHash(path)
	if err != nil {
		return "" // not fatal: the manager treats an absent hash as unknown, never as clean
	}

	hashCacheMu.Lock()
	if len(hashCache) >= maxHashCache {
		hashCache = make(map[string]hashEntry, maxHashCache)
	}
	hashCache[path] = hashEntry{hash: hash, size: fi.Size(), modTime: fi.ModTime(), at: time.Now()}
	hashCacheMu.Unlock()

	return hash
}

// computeFileHash computes the SHA-256 of the file at path.
//
// SHA-256, not MD5: this digest is sent to VirusTotal and is the identity a malicious binary
// would want to forge, and it is also the key the rest of DeusWatch stores hashes under
// (file_hash_reputation.sha256, FIM sightings), so an MD5 here could never be cross-referenced
// with either.
func computeFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Skipped, not truncated. Hashing a prefix produces a digest belonging to no file at all, so
	// every reputation lookup for it misses while reading as an ordinary clean result.
	// maxHashBytes is FIM's own cap, reused so the agent has one answer to "how big is too big".
	//
	// FAIL CLOSED on a Stat error. Treating it as "no size limit known, hash anyway" put the
	// truncated-prefix digest straight back for any file over the cap, which is the exact bug this
	// guard exists to prevent. No hash at all is honest; a hash of the first 64MiB is not.
	fi, serr := f.Stat()
	if serr != nil {
		return "", fmt.Errorf("stat for hashing: %w", serr)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	if fi.Size() > maxHashBytes {
		return "", fmt.Errorf("file too large to hash: %d bytes", fi.Size())
	}

	hasher := sha256.New()
	// LimitReader still, as a backstop: the file may grow between the Stat above and this read,
	// and a digest of a moving file is not reproducible anyway.
	n, err := io.Copy(hasher, io.LimitReader(f, maxHashBytes))
	if err != nil {
		return "", err
	}
	if n != fi.Size() {
		// Short or long read means the file changed underneath us. A digest of a file that no
		// longer exists in that form is worse than none: it will never match anything.
		return "", fmt.Errorf("file changed while hashing: read %d of %d bytes", n, fi.Size())
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// collectProcesses is implemented by the platform-specific files with matching //go:build tags:
//   - process_snapshot_linux.go   (linux)
//   - process_snapshot_windows.go (windows)
//   - process_snapshot_other.go   (everything else, no-op fallback)
// Go has no forward-declaration syntax, so this cross-OS package works purely by build-tag
// selection, DO NOT add a body-less declaration of collectProcesses here or every OS will
// double-define the symbol and the build fails.

// CollectProcessSnapshotBatch gathers all processes and wraps them in a timestamped batch.
func CollectProcessSnapshotBatch() (*ProcessSnapshotBatch, error) {
	processes, err := collectProcesses()
	if err != nil {
		return nil, err
	}

	return &ProcessSnapshotBatch{
		Timestamp: time.Now(),
		Processes: processes,
	}, nil
}

// ClearHashCache clears the in-memory hash cache. Useful for testing.
func ClearHashCache() {
	hashCacheMu.Lock()
	defer hashCacheMu.Unlock()
	hashCache = make(map[string]hashEntry)
}

// HashCacheSize returns the current size of the hash cache.
func HashCacheSize() int {
	hashCacheMu.RLock()
	defer hashCacheMu.RUnlock()
	return len(hashCache)
}
