package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// isInotifyLimit reports whether err is the kernel refusing another inotify instance/watch because
// a per-user limit is exhausted: EMFILE/ENFILE (max_user_instances, out of instance slots) or
// ENOSPC (max_user_watches). Used only to print a more actionable hint — the constants exist on
// every platform, so this compiles everywhere and is simply never true off Linux.
func isInotifyLimit(err error) bool {
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOSPC)
}

// startFIMWatcher watches the FIM roots with fsnotify (inotify / ReadDirectoryChangesW / kqueue)
// and sends a debounced signal on trigger whenever anything under them changes, so FIM detection
// is real-time instead of waiting for the poll interval. Directories are watched recursively and
// newly-created sub-directories are added on the fly. The watcher is only a TRIGGER - the FIM
// Scan() still re-reads the tree to compute the actual change, so a missed/duplicated event only
// affects latency, never correctness (the safety-net poll remains). Returns a closer; on error
// the caller falls back to poll-only.
func startFIMWatcher(ctx context.Context, roots []string, debounce time.Duration, trigger chan<- struct{}) (func(), error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	added := 0
	for _, r := range roots {
		added += addWatchRecursive(w, r)
	}
	if added == 0 {
		w.Close()
		return nil, fmt.Errorf("no watchable paths in %v (do they exist yet?)", roots)
	}
	go func() {
		var timer *time.Timer
		fire := func() {
			select {
			case trigger <- struct{}{}:
			default: // a scan is already queued
			}
		}
		for {
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				w.Close()
				return
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				// A new directory under a watched root must itself be watched.
				if ev.Op&fsnotify.Create != 0 {
					if fi, serr := os.Stat(ev.Name); serr == nil && fi.IsDir() {
						addWatchRecursive(w, ev.Name)
					}
				}
				// Debounce: coalesce a burst of events into one scan.
				if timer == nil {
					timer = time.AfterFunc(debounce, fire)
				} else {
					timer.Reset(debounce)
				}
			case werr, ok := <-w.Errors:
				if !ok {
					return
				}
				log.Printf("agent: fim watcher: %v", werr)
			}
		}
	}()
	return func() { w.Close() }, nil
}

// addWatchRecursive adds path (and, for a directory, every sub-directory) to the watcher.
// Watching directories is enough: fsnotify reports events for files inside a watched dir.
// Add errors (e.g. inotify watch-limit exhaustion) are ignored per path - the poll safety-net
// still covers anything not watched. Returns how many watches were added.
func addWatchRecursive(w *fsnotify.Watcher, path string) int {
	fi, err := os.Stat(path)
	if err != nil {
		return 0 // may not exist yet; the poll safety-net catches it when created
	}
	if !fi.IsDir() {
		if w.Add(path) == nil {
			return 1
		}
		return 0
	}
	added := 0
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil // skip unreadable subtrees, keep walking
		}
		if d.IsDir() {
			if w.Add(p) == nil {
				added++
			}
		}
		return nil
	})
	return added
}
