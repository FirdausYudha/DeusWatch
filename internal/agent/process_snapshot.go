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

// hashFileCache stores computed hashes to avoid re-hashing the same file.
var (
	hashCacheMu sync.RWMutex
	hashCache   = make(map[string]string) // path -> SHA-256 hash
)

// getOrComputeHash returns the SHA-256 hash of a file, using cache to avoid repeated work.
func getOrComputeHash(path string) string {
	hashCacheMu.RLock()
	if cached, ok := hashCache[path]; ok {
		hashCacheMu.RUnlock()
		return cached
	}
	hashCacheMu.RUnlock()

	hash, err := computeFileHash(path)
	if err != nil {
		return "" // silently fail, hash is not critical
	}

	hashCacheMu.Lock()
	hashCache[path] = hash
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

	// Skipped, not truncated. The old code hashed the first 32MB and returned that as the file's
	// hash: for anything larger it produced a digest belonging to no file at all, so every
	// VirusTotal lookup missed while reading as an ordinary clean result. maxHashBytes is FIM's
	// own cap, reused so the agent has one answer to "how big is too big to hash".
	if fi, serr := f.Stat(); serr == nil {
		if !fi.Mode().IsRegular() {
			return "", fmt.Errorf("not a regular file")
		}
		if fi.Size() > maxHashBytes {
			return "", fmt.Errorf("file too large to hash: %d bytes", fi.Size())
		}
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(f, maxHashBytes)); err != nil {
		return "", err
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
	hashCache = make(map[string]string)
}

// HashCacheSize returns the current size of the hash cache.
func HashCacheSize() int {
	hashCacheMu.RLock()
	defer hashCacheMu.RUnlock()
	return len(hashCache)
}
