package agent

// File Integrity Monitoring (FIM) — design doc agent roadmap.
//
// A source of type "fim" monitors files/directories: every interval they are hashed
// (SHA-256) and compared to a baseline. Changes (created/modified/deleted) are emitted
// as a Line with dataset "fim" carrying a JSON payload, then normalized by the gateway
// into a DCS Event with file.* fields (see ingest.normalizeFIM). This approach rides on
// the existing RawLog pipeline instead of a separate binary path.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// fimScanInterval is the default interval between FIM scans.
const fimScanInterval = 60 * time.Second

// maxHashBytes limits the size of a file that gets hashed (huge files skip hashing,
// only metadata is tracked) so scans don't overload I/O.
const maxHashBytes = 64 << 20 // 64 MiB

// FIMChange is a single file-integrity change (the JSON payload of dataset "fim").
type FIMChange struct {
	Path   string `json:"path"`
	Action string `json:"action"` // created | modified | deleted
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

type fileState struct {
	sha256 string
	size   int64
	mode   string
}

// FIMScanner tracks an integrity baseline for a set of roots (files/directories)
// and computes changes each time Scan is called.
type FIMScanner struct {
	roots    []string
	baseline map[string]fileState
	primed   bool
}

// NewFIMScanner creates a scanner for the given roots (files or directories).
func NewFIMScanner(roots ...string) *FIMScanner {
	return &FIMScanner{roots: roots, baseline: map[string]fileState{}}
}

// splitFIMPaths splits a FIM source's Path into a list of roots (comma-separated).
func splitFIMPaths(path string) []string {
	var out []string
	for _, p := range strings.Split(path, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Scan scans all roots and returns the changes since the previous Scan. The FIRST
// call only builds the baseline (returns nil) so existing files are not mistakenly
// reported as "created".
func (s *FIMScanner) Scan() ([]FIMChange, error) {
	current := map[string]fileState{}
	for _, root := range s.roots {
		if err := s.walk(root, current); err != nil {
			return nil, err
		}
	}

	if !s.primed {
		s.baseline = current
		s.primed = true
		return nil, nil
	}

	var changes []FIMChange
	for path, cur := range current {
		prev, ok := s.baseline[path]
		switch {
		case !ok:
			changes = append(changes, change(path, "created", cur))
		case prev.sha256 != cur.sha256 || prev.size != cur.size || prev.mode != cur.mode:
			changes = append(changes, change(path, "modified", cur))
		}
	}
	for path, prev := range s.baseline {
		if _, ok := current[path]; !ok {
			changes = append(changes, change(path, "deleted", prev))
		}
	}
	s.baseline = current
	return changes, nil
}

func change(path, action string, st fileState) FIMChange {
	c := FIMChange{Path: path, Action: action, Size: st.size, Mode: st.mode}
	if action != "deleted" {
		c.SHA256 = st.sha256
	}
	return c
}

// walk fills dst with the state of each regular file under root (a single file is
// also supported). Unreadable files are skipped with a log, not failing the scan.
func (s *FIMScanner) walk(root string, dst map[string]fileState) error {
	info, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // root doesn't exist yet — change detected when created later
		}
		return err
	}
	if !info.IsDir() {
		if info.Mode().IsRegular() {
			if st, ok := stateOf(root, info); ok {
				dst[root] = st
			}
		}
		return nil
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("agent: fim: skip %s: %v", p, err)
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if st, ok := stateOf(p, fi); ok {
			dst[p] = st
		}
		return nil
	})
}

func stateOf(path string, info os.FileInfo) (fileState, bool) {
	st := fileState{size: info.Size(), mode: info.Mode().Perm().String()}
	if info.Size() <= maxHashBytes {
		if h, err := hashFile(path); err == nil {
			st.sha256 = h
		} else {
			log.Printf("agent: fim: hash %s failed: %v", path, err)
			return fileState{}, false
		}
	}
	return st, true
}

func hashFile(path string) (string, error) {
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

// collectFIM runs periodic FIM scans for one source, emitting a Line with the source's
// dataset for each change until ctx is cancelled.
func collectFIM(ctx context.Context, s Source, out chan<- Line) error {
	roots := splitFIMPaths(s.Path)
	if len(roots) == 0 {
		return fmt.Errorf("fim source %q: empty Path", s.Dataset)
	}
	scanner := NewFIMScanner(roots...)
	if _, err := scanner.Scan(); err != nil { // build the initial baseline
		log.Printf("agent: fim %q: baseline scan: %v", s.Dataset, err)
	}

	t := time.NewTicker(s.scanInterval(fimScanInterval))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			changes, err := scanner.Scan()
			if err != nil {
				log.Printf("agent: fim %q: scan: %v", s.Dataset, err)
				continue
			}
			for _, c := range changes {
				body, err := json.Marshal(c)
				if err != nil {
					continue
				}
				select {
				case out <- Line{Dataset: s.Dataset, Message: string(body)}:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}
