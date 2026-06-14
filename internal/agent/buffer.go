package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Buffer is a disk-based store-and-forward (design doc section 13): batches that fail
// to send are stored as files and resent when the manager comes back online.
type Buffer struct {
	dir string
	max int // max number of files; the oldest are dropped when exceeded
	mu  sync.Mutex
}

var bufSeq atomic.Uint64

// NewBuffer creates a buffer in dir (created if it doesn't exist).
func NewBuffer(dir string, max int) (*Buffer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if max <= 0 {
		max = 1000
	}
	return &Buffer{dir: dir, max: max}, nil
}

// Save writes one batch (raw JSON) to the buffer then prunes if it exceeds max.
func (b *Buffer) Save(body []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	name := fmt.Sprintf("%020d-%06d.json", time.Now().UnixNano(), bufSeq.Add(1)%1000000)
	if err := os.WriteFile(filepath.Join(b.dir, name), body, 0o600); err != nil {
		return err
	}
	return b.prune()
}

// Pending returns the buffer file paths, oldest first.
func (b *Buffer) Pending() ([]string, error) {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			files = append(files, filepath.Join(b.dir, e.Name()))
		}
	}
	sort.Strings(files) // timestamp prefix -> oldest-first order
	return files, nil
}

// Remove deletes one buffer file (after a successful resend).
func (b *Buffer) Remove(path string) error { return os.Remove(path) }

// prune drops the oldest files when the count exceeds max. (called while holding the lock)
func (b *Buffer) prune() error {
	files, err := b.Pending()
	if err != nil || len(files) <= b.max {
		return err
	}
	for _, f := range files[:len(files)-b.max] {
		_ = os.Remove(f)
	}
	return nil
}
