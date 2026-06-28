package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// FileTarget is a known-bad file the manager flagged (path + expected SHA-256).
type FileTarget struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// DefaultQuarantineDir is the per-OS directory quarantined files are moved into.
func DefaultQuarantineDir() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\DeusWatch\quarantine`
	}
	return "/var/lib/deuswatch/quarantine"
}

// fileSHA256 returns the lowercase hex SHA-256 of the file at path.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RemediateFile acts on a flagged file ONLY if its current SHA-256 still equals wantHash —
// so a file that was changed, cleaned, or replaced since detection is never touched (the key
// safety against false positives). mode "delete" removes it; anything else quarantines it
// (moves into dir, read-only). A missing or hash-mismatched file is a safe no-op.
func RemediateFile(path, wantHash, mode, dir string) (bool, error) {
	if path == "" || len(wantHash) != 64 {
		return false, nil
	}
	got, err := fileSHA256(path)
	if err != nil {
		return false, nil // missing/unreadable — not ours to touch
	}
	if !strings.EqualFold(got, wantHash) {
		return false, nil // changed since detection — never touch
	}
	if strings.EqualFold(mode, "delete") {
		return true, os.Remove(path)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	dest := filepath.Join(dir, filepath.Base(path)+"."+wantHash[:12]+"."+time.Now().Format("20060102T150405")+".quarantine")
	if err := moveFile(path, dest); err != nil {
		return false, err
	}
	_ = os.Chmod(dest, 0o400)
	return true, nil
}

// moveFile renames src to dst, falling back to copy+remove across filesystems.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		in.Close()
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		in.Close()
		out.Close()
		return err
	}
	in.Close()
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}
