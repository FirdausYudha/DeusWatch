package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultSnapshotDir is the per-OS directory where FIM known-good snapshots are kept.
func DefaultSnapshotDir() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\DeusWatch\fim-snapshots`
	}
	return "/var/lib/deuswatch/fim-snapshots"
}

// SnapshotStore persists a "known-good" copy of each watched small text file so a
// defaced/modified file can be restored to it on one click. The snapshot is written the
// FIRST time a file is seen (presumed clean at FIM setup) and is NOT overwritten when the
// file later changes - so restore always reverts to the original good version and survives
// an agent restart. (A future "accept current as baseline" action can refresh it.)
type SnapshotStore struct{ dir string }

// NewSnapshotStore creates the store under dir (created if missing). Returns nil when dir
// is empty (snapshots disabled - diff still works, restore doesn't).
func NewSnapshotStore(dir string) (*SnapshotStore, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("agent: fim snapshot dir: %w", err)
	}
	return &SnapshotStore{dir: dir}, nil
}

// key maps an absolute file path to a stable snapshot filename.
func (s *SnapshotStore) key(path string) string {
	h := sha256.Sum256([]byte(path))
	return filepath.Join(s.dir, hex.EncodeToString(h[:]))
}

// Ensure writes content as the snapshot for path only if one does not already exist, so the
// original good version is preserved across later changes and restarts. No-op if s is nil.
func (s *SnapshotStore) Ensure(path, content string) {
	if s == nil {
		return
	}
	k := s.key(path)
	if _, err := os.Stat(k); err == nil {
		return // already have the known-good snapshot
	}
	// 0600: the snapshot may contain sensitive config content.
	_ = os.WriteFile(k, []byte(content), 0o600)
}

// Read returns the snapshot content for path (ok=false when none/disabled).
func (s *SnapshotStore) Read(path string) (string, bool) {
	if s == nil {
		return "", false
	}
	b, err := os.ReadFile(s.key(path))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// Restore writes the known-good snapshot back to path atomically (temp file + rename), so a
// reader never sees a half-written file. Returns an error if there is no snapshot for path.
func (s *SnapshotStore) Restore(path string) error {
	content, ok := s.Read(path)
	if !ok {
		return fmt.Errorf("no snapshot for %q (nothing to restore)", path)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".deuswatch-restore-*")
	if err != nil {
		return fmt.Errorf("restore %q: temp: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("restore %q: write: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("restore %q: close: %w", path, err)
	}
	// Preserve the target's permissions if it still exists.
	if fi, err := os.Stat(path); err == nil {
		_ = os.Chmod(tmpName, fi.Mode().Perm())
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("restore %q: rename: %w", path, err)
	}
	return nil
}
