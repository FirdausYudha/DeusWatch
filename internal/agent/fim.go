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

// fimSnapshots is the process-wide known-good snapshot store shared by all FIM sources
// (for one-click restore). Set once at agent startup via SetFIMSnapshots; nil = disabled.
var fimSnapshots *SnapshotStore

// SetFIMSnapshots enables restore snapshots for FIM sources. Call once at startup.
func SetFIMSnapshots(s *SnapshotStore) { fimSnapshots = s }

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
	Diff   string `json:"diff,omitempty"` // unified line diff (small text files only)
	// Who-data (Linux/auditd only): the process/user that caused the change. Empty when
	// who-data is disabled or no audit record correlated to this path.
	Actor    string `json:"actor,omitempty"`     // process name (comm)
	ActorExe string `json:"actor_exe,omitempty"` // process executable path
	ActorPID int    `json:"actor_pid,omitempty"`
	User     string `json:"user,omitempty"`    // login user (auid) or uid
	Syscall  string `json:"syscall,omitempty"` // the syscall that changed the file
}

type fileState struct {
	sha256 string
	size   int64
	mode   string
	// content is a snapshot of the file (small text files only) used to compute a diff on
	// the next change and, later, one-click restore. Empty for binaries/large files.
	content string
	isText  bool
}

// FIMScanner tracks an integrity baseline for a set of roots (files/directories)
// and computes changes each time Scan is called.
type FIMScanner struct {
	roots    []string
	baseline map[string]fileState
	primed   bool
	snaps    *SnapshotStore // known-good copies for one-click restore (nil = disabled)
	who      WhoDataSource  // who-data attribution (nil = disabled / non-Linux)
}

// NewFIMScanner creates a scanner for the given roots (files or directories).
func NewFIMScanner(roots ...string) *FIMScanner {
	return &FIMScanner{roots: roots, baseline: map[string]fileState{}}
}

// WithSnapshots attaches a snapshot store so each watched text file's original content is
// persisted for restore. Returns the scanner for chaining.
func (s *FIMScanner) WithSnapshots(store *SnapshotStore) *FIMScanner {
	s.snaps = store
	return s
}

// WithWhoData attaches a who-data source so each change is attributed to the process/user that
// made it (Linux/auditd). Returns the scanner for chaining.
func (s *FIMScanner) WithWhoData(w WhoDataSource) *FIMScanner {
	s.who = w
	return s
}

// attachWho enriches a change with the actor that touched its path, if who-data is available.
func (s *FIMScanner) attachWho(c *FIMChange) {
	if s.who == nil {
		return
	}
	if who, ok := s.who.Lookup(c.Path); ok {
		c.Actor, c.ActorExe, c.ActorPID = who.Actor, who.Exe, who.PID
		c.User, c.Syscall = who.User, who.Syscall
	}
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

	// Persist a known-good snapshot of each text file the first time it's seen (for restore).
	if s.snaps != nil {
		for path, st := range current {
			if st.isText {
				s.snaps.Ensure(path, st.content)
			}
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
			c := change(path, "created", cur)
			s.attachWho(&c)
			changes = append(changes, c)
		case prev.sha256 != cur.sha256 || prev.size != cur.size || prev.mode != cur.mode:
			c := change(path, "modified", cur)
			// Superior FIM: show WHICH lines changed when both versions are snapshotted text.
			if prev.isText && cur.isText {
				c.Diff = unifiedDiff(prev.content, cur.content)
			}
			s.attachWho(&c)
			changes = append(changes, c)
		}
	}
	for path, prev := range s.baseline {
		if _, ok := current[path]; !ok {
			c := change(path, "deleted", prev)
			s.attachWho(&c)
			changes = append(changes, c)
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
	// Small files: read once, use the bytes for both the hash and (if text) the content
	// snapshot - so we can diff/restore later without a second read.
	if info.Size() <= maxSnapshotBytes {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Printf("agent: fim: read %s failed: %v", path, err)
			return fileState{}, false
		}
		st.sha256 = hashBytes(b)
		if isProbablyText(b) {
			st.content = string(b)
			st.isText = true
		}
		return st, true
	}
	// Larger files: hash only, no snapshot (skip hashing beyond maxHashBytes).
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

func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
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

// collectFIM runs FIM scans for one source, emitting a Line with the source's dataset for each
// change until ctx is cancelled. Detection is real-time via fsnotify (a filesystem event fires
// an immediate rescan), with interval polling kept as a safety net; set FIM_REALTIME=0 to poll
// only. The Scan() is the source of truth either way, so a missed watch only adds latency.
func collectFIM(ctx context.Context, s Source, out chan<- Line) error {
	roots := splitFIMPaths(s.Path)
	if len(roots) == 0 {
		return fmt.Errorf("fim source %q: empty Path", s.Dataset)
	}
	scanner := NewFIMScanner(roots...).WithSnapshots(fimSnapshots).WithWhoData(fimWhoData)
	if _, err := scanner.Scan(); err != nil { // build the initial baseline
		log.Printf("agent: fim %q: baseline scan: %v", s.Dataset, err)
	}

	scanAndEmit := func() {
		changes, err := scanner.Scan()
		if err != nil {
			log.Printf("agent: fim %q: scan: %v", s.Dataset, err)
			return
		}
		for _, c := range changes {
			body, err := json.Marshal(c)
			if err != nil {
				continue
			}
			select {
			case out <- Line{Dataset: s.Dataset, Message: string(body)}:
			case <-ctx.Done():
				return
			}
		}
	}

	// Real-time triggering via fsnotify (unless disabled); polling remains as a safety net.
	trigger := make(chan struct{}, 1)
	realtime := false
	if os.Getenv("FIM_REALTIME") != "0" {
		if closeWatcher, err := startFIMWatcher(ctx, roots, 500*time.Millisecond, trigger); err != nil {
			log.Printf("agent: fim %q: real-time watch unavailable, polling only: %v", s.Dataset, err)
		} else {
			defer closeWatcher()
			realtime = true
			log.Printf("agent: fim %q: real-time watch active (fsnotify) + safety poll", s.Dataset)
		}
	}
	// When the watcher is active it catches changes instantly, so the poll is only a backstop
	// (never faster than 1m); without it, honor the configured scan interval.
	poll := s.scanInterval(fimScanInterval)
	if realtime && poll < time.Minute {
		poll = time.Minute
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			scanAndEmit()
		case <-trigger:
			scanAndEmit()
		}
	}
}
