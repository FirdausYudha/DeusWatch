// Package archive writes a raw, per-source daily log archive (zstd), the LST Tameng "Lapis 2"
// raw archive. Every event that reaches the pipeline is appended (its original line, or the
// normalized JSON when there is no original) to a file laid out as:
//
//	<dir>/<source>/<dataset>/<YYYY-MM-DD>.log.zst
//
// e.g. opnsense-a/modsecurity/2026-07-17.log.zst. Files hold concatenated zstd frames (which
// `zstd -d` / any zstd reader decompresses transparently), so appends are cheap and crash-safe:
// a flush writes one self-contained frame, so a torn write only loses the last (unsynced) block.
package archive

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

// Archiver buffers raw lines per (source, dataset, day) and periodically flushes each buffer as a
// compressed frame appended to its file. Safe for concurrent Add.
type Archiver struct {
	dir           string
	flushEvery    time.Duration
	retentionDays int

	mu  sync.Mutex
	buf map[string]*entry // key = relative file path
	enc *zstd.Encoder
}

type entry struct {
	path string // absolute file path
	b    bytes.Buffer
}

// New builds an Archiver rooted at dir. flushEvery bounds how long a line stays only in memory;
// retentionDays > 0 deletes archive files older than that (0 = keep forever).
func New(dir string, flushEvery time.Duration, retentionDays int) (*Archiver, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("archive: mkdir %s: %w", dir, err)
	}
	// A shared stateless encoder (no dictionary) — EncodeAll produces one independent frame.
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, err
	}
	if flushEvery <= 0 {
		flushEvery = 10 * time.Second
	}
	return &Archiver{dir: dir, flushEvery: flushEvery, retentionDays: retentionDays, buf: map[string]*entry{}, enc: enc}, nil
}

// Add appends one raw line for a source/dataset, dated by t (server-local day).
func (a *Archiver) Add(source, dataset, line string, t time.Time) {
	if strings.TrimSpace(line) == "" {
		return
	}
	rel := filepath.Join(safeSeg(source, "unknown"), safeSeg(dataset, "raw"), t.Format("2006-01-02")+".log.zst")
	a.mu.Lock()
	e := a.buf[rel]
	if e == nil {
		e = &entry{path: filepath.Join(a.dir, rel)}
		a.buf[rel] = e
	}
	e.b.WriteString(line)
	if !strings.HasSuffix(line, "\n") {
		e.b.WriteByte('\n')
	}
	a.mu.Unlock()
}

// Run flushes on an interval until ctx is cancelled, then flushes once more so nothing buffered
// is lost on shutdown. It also runs the retention sweep after each flush.
func (a *Archiver) Run(ctx context.Context) {
	t := time.NewTicker(a.flushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			a.Flush()
			return
		case <-t.C:
			a.Flush()
			a.sweep()
		}
	}
}

// Flush compresses each non-empty buffer and appends it as a frame to its file.
func (a *Archiver) Flush() {
	a.mu.Lock()
	pending := make([]*entry, 0, len(a.buf))
	for key, e := range a.buf {
		if e.b.Len() == 0 {
			continue
		}
		// Take the bytes and reset the shared buffer while holding the lock.
		raw := append([]byte(nil), e.b.Bytes()...)
		e.b.Reset()
		pending = append(pending, &entry{path: e.path, b: *bytes.NewBuffer(raw)})
		_ = key
	}
	a.mu.Unlock()

	for _, e := range pending {
		if err := a.appendFrame(e.path, e.b.Bytes()); err != nil {
			log.Printf("archive: write %s: %v", e.path, err)
		}
	}
}

func (a *Archiver) appendFrame(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	frame := a.enc.EncodeAll(raw, nil) // one self-contained zstd frame
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(frame)
	return err
}

// sweep deletes archive files older than the retention window (no-op when disabled).
func (a *Archiver) sweep() {
	if a.retentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -a.retentionDays)
	_ = filepath.WalkDir(a.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".log.zst") {
			return nil
		}
		if fi, e := d.Info(); e == nil && fi.ModTime().Before(cutoff) {
			_ = os.Remove(p)
		}
		return nil
	})
}

// safeSeg makes a path segment safe: no separators / traversal, printable, non-empty.
func safeSeg(s, fallback string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == '/', r == '\\', r == ' ':
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._")
	if out == "" || out == ".." {
		return fallback
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}
