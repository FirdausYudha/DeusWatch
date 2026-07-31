package agent

import (
	"crypto/md5"
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
	Name      string    `json:"name"`       // e.g. "svchost.exe", "chrome"
	ParentPID int       `json:"parent_pid"`
	Cmdline   string    `json:"cmdline"`
	User      string    `json:"user"`       // owner of process (UID on Linux, username on Windows)
	Path      string    `json:"path"`       // full path to executable
	StartTime time.Time `json:"start_time"`
	MemoryMB  uint64    `json:"memory_mb"`
	FileHash  string    `json:"file_hash"` // MD5 of executable
}

// ProcessSnapshotBatch is a collection of process snapshots from one agent at a point in time.
type ProcessSnapshotBatch struct {
	Timestamp time.Time         `json:"timestamp"`
	Processes []ProcessSnapshot `json:"processes"`
}

// hashFileCache stores computed hashes to avoid re-hashing the same file.
var (
	hashCacheMu sync.RWMutex
	hashCache   = make(map[string]string) // path -> MD5 hash
)

// getOrComputeHash returns the MD5 hash of a file, using cache to avoid repeated work.
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

// computeFileHash computes MD5 hash of file at path. Returns empty string on error.
func computeFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := md5.New()
	// Limit read to avoid huge files (just hash first 32MB)
	_, err = io.CopyN(hasher, f, 32*1024*1024)
	if err != nil && err != io.EOF {
		return "", err
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// collectProcesses is implemented by the platform-specific files with matching //go:build tags:
//   - process_snapshot_linux.go   (linux)
//   - process_snapshot_windows.go (windows)
//   - process_snapshot_other.go   (everything else — no-op fallback)
// Go has no forward-declaration syntax, so this cross-OS package works purely by build-tag
// selection — DO NOT add a body-less declaration of collectProcesses here or every OS will
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
