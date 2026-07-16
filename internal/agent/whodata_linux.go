//go:build linux

package agent

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

// auditKey is the audit filter key DeusWatch tags its FIM watch rules with, so we only read our
// own who-data out of the shared audit stream.
const auditKey = "deuswatch_fim"

// whoTTL bounds how long a cached actor stays valid — a change is correlated with a who-data
// record seen within this window. Kept short so a stale actor is never attributed to a change.
const whoTTL = 30 * time.Second

// auditWatcher installs audit watch rules on the FIM roots and tails the audit log, keeping a
// short-lived map of path -> who so the FIM scanner can attribute each change. It requires root
// and a running auditd (the audit log must be readable); if either is missing it stays inert and
// Lookup returns false, so FIM keeps working without who-data.
type auditWatcher struct {
	mu    sync.Mutex
	cache map[string]whoEntry
}

type whoEntry struct {
	who WhoData
	at  time.Time
}

// StartWhoData installs watch rules on dirs and starts tailing the audit log. A non-nil error
// means who-data could not be enabled (caller logs it and continues without who-data).
func StartWhoData(ctx context.Context, dirs []string, logPath string) (WhoDataSource, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("who-data needs root (audit rules); running as uid %d", os.Geteuid())
	}
	if _, err := exec.LookPath("auditctl"); err != nil {
		return nil, fmt.Errorf("auditctl not found — install auditd for who-data")
	}
	if logPath == "" {
		logPath = "/var/log/audit/audit.log"
	}
	if _, err := os.Stat(logPath); err != nil {
		return nil, fmt.Errorf("audit log %s not readable: %w", logPath, err)
	}
	w := &auditWatcher{cache: map[string]whoEntry{}}
	installed := 0
	for _, d := range dirs {
		// -w <dir> -p wa -k deuswatch_fim : watch writes+attribute changes, tagged with our key.
		cmd := exec.CommandContext(ctx, "auditctl", "-w", d, "-p", "wa", "-k", auditKey)
		if out, err := cmd.CombinedOutput(); err != nil {
			// A persistent kernel audit rule survives an agent restart, so on any restart
			// auditctl reports "Rule exists" - that means the path IS being watched, which is
			// exactly what we want. Treat it as installed (not a failure).
			if strings.Contains(string(out), "Rule exists") {
				installed++
				continue
			}
			log.Printf("agent: who-data: add audit rule for %s failed: %v (%s)", d, err, strings.TrimSpace(string(out)))
			continue
		}
		installed++
	}
	if installed == 0 {
		return nil, fmt.Errorf("no audit rules could be installed for %v", dirs)
	}
	go w.tail(ctx, logPath)
	go w.prune(ctx)
	log.Printf("agent: who-data active (audit watch on %d path(s), key=%s)", installed, auditKey)
	return w, nil
}

// Lookup returns the most recent actor for path within whoTTL.
func (w *auditWatcher) Lookup(p string) (WhoData, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	e, ok := w.cache[p]
	if !ok || time.Since(e.at) > whoTTL {
		return WhoData{}, false
	}
	return e.who, true
}

func (w *auditWatcher) put(p string, who WhoData) {
	w.mu.Lock()
	w.cache[p] = whoEntry{who: who, at: time.Now()}
	w.mu.Unlock()
}

// prune drops expired cache entries so a long-running agent doesn't grow the map unbounded.
func (w *auditWatcher) prune(ctx context.Context) {
	t := time.NewTicker(whoTTL)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.mu.Lock()
			for p, e := range w.cache {
				if time.Since(e.at) > whoTTL {
					delete(w.cache, p)
				}
			}
			w.mu.Unlock()
		}
	}
}

// tail follows the audit log from its current end, grouping records by audit event id and
// resolving each completed event into who-data. It handles rotation/truncation by reopening
// when the file shrinks. Reading the log (rather than the audit netlink socket) avoids
// contending with auditd, which owns that socket.
func (w *auditWatcher) tail(ctx context.Context, logPath string) {
	var offset int64
	if fi, err := os.Stat(logPath); err == nil {
		offset = fi.Size() // start at the end: only new events
	}
	var (
		curID string
		group []string
	)
	flush := func() {
		if len(group) == 0 {
			return
		}
		w.consume(group)
		group = group[:0]
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		fi, err := os.Stat(logPath)
		if err != nil {
			continue
		}
		if fi.Size() < offset { // rotated/truncated
			offset = 0
			curID, group = "", group[:0]
		}
		if fi.Size() == offset {
			continue
		}
		f, err := os.Open(logPath)
		if err != nil {
			continue
		}
		if _, err := f.Seek(offset, 0); err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				line := sc.Text()
				id := auditEventID(line)
				if id != curID && curID != "" {
					flush()
				}
				curID = id
				group = append(group, line)
			}
			flush() // records for an event are contiguous; flush the trailing group each read
			curID = ""
		}
		if fi2, err := f.Stat(); err == nil {
			offset = fi2.Size()
		}
		f.Close()
	}
}

// consume parses one event's records and, if it is one of our keyed FIM events, caches the
// actor for every path it touched (resolving the numeric user to a name where possible).
func (w *auditWatcher) consume(lines []string) {
	ev := parseAuditEvent(lines, auditKey)
	if !ev.keyed || len(ev.paths) == 0 {
		return
	}
	ev.who.User = resolveUser(ev.who.User)
	for _, p := range ev.paths {
		w.put(p, ev.who)
	}
}

// resolveUser turns a numeric uid into "name(uid)" when it resolves, else leaves it numeric.
func resolveUser(uid string) string {
	if uid == "" {
		return ""
	}
	if _, err := strconv.Atoi(uid); err != nil {
		return uid // already a name
	}
	if u, err := user.LookupId(uid); err == nil && u.Username != "" {
		return u.Username + "(" + uid + ")"
	}
	return uid
}
