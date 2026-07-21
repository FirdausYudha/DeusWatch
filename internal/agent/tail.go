// Package agent is the DeusWatch endpoint log collector: it tails log files and
// sends raw lines to the gateway over mTLS.
package agent

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// tailReopenPoll is how often a tailer at EOF re-checks the path for rotation/truncation and
// re-attempts opening a file that isn't there yet.
const tailReopenPoll = 500 * time.Millisecond

// FollowFile reads lines from path and sends them to out. If fromStart is true it starts from the
// beginning of the file; otherwise from the end (only new lines). After reaching EOF it keeps
// following for new lines until ctx is cancelled.
//
// It survives the two things that silently killed a naive tailer in production:
//
//   - LOG ROTATION. When logrotate renames auth.log -> auth.log.1 and the writer starts a fresh
//     auth.log, an fd opened on the old inode would sit at EOF forever and the source would go
//     quiet until the agent restarted. FollowFile drains the old file, notices (by inode identity)
//     that the path now names a different file, and reopens it from the start. copytruncate-style
//     rotation (same inode, size reset to 0) is detected as truncation and re-read from the top.
//
//   - A FILE THAT ISN'T THERE YET. A source path that doesn't exist at start (e.g. /var/log/ufw.log
//     before firewall logging is switched on, or the brief gap mid-rotation) no longer kills the
//     source. FollowFile waits for the file to appear instead of returning an error.
func FollowFile(ctx context.Context, path string, fromStart bool, out chan<- string) error {
	// openFollow opens path, optionally seeking to the end. It waits for the file to appear rather
	// than failing when it is missing, so a not-yet-created log doesn't kill the source. Returns
	// the file, its identity (for rotation detection) and the starting byte offset.
	openFollow := func(seekEnd bool) (*os.File, os.FileInfo, int64, error) {
		announcedWait := false
		for {
			f, err := os.Open(path)
			if err == nil {
				info, serr := f.Stat()
				if serr != nil {
					f.Close()
					return nil, nil, 0, serr
				}
				var off int64
				if seekEnd {
					if off, err = f.Seek(0, io.SeekEnd); err != nil {
						f.Close()
						return nil, nil, 0, err
					}
				}
				if announcedWait {
					log.Printf("agent: tail %q: file appeared, following", path)
				}
				return f, info, off, nil
			}
			if !os.IsNotExist(err) {
				return nil, nil, 0, err
			}
			// A file we had to WAIT for has no accumulated history to skip — it comes into
			// existence fresh — so read it from the start even when tailing "from end". Otherwise
			// a log that appears after switch-on (e.g. ufw.log) would lose its first entries.
			seekEnd = false
			if !announcedWait {
				log.Printf("agent: tail %q: not present yet, waiting for it to appear", path)
				announcedWait = true
			}
			select {
			case <-ctx.Done():
				return nil, nil, 0, ctx.Err()
			case <-time.After(tailReopenPoll):
			}
		}
	}

	f, openInfo, offset, err := openFollow(!fromStart)
	if err != nil {
		if ctx.Err() != nil {
			return nil // shutdown while waiting for the file — not an error
		}
		return err
	}
	defer func() { f.Close() }()
	reader := bufio.NewReader(f)

	for {
		line, rerr := reader.ReadString('\n')
		if line != "" {
			offset += int64(len(line))
			if trimmed := strings.TrimRight(line, "\r\n"); trimmed != "" {
				select {
				case out <- trimmed:
				case <-ctx.Done():
					return nil
				}
			}
		}
		switch {
		case rerr == io.EOF:
			// At EOF: decide whether the file we hold is still the file the path names.
			switch classifyPath(path, openInfo, offset) {
			case pathRotated:
				// A new file wears this name now. We have already drained the old fd to EOF, so
				// close it and follow the new file from its beginning.
				log.Printf("agent: tail %q: rotation detected, reopening", path)
				f.Close()
				f, openInfo, offset, err = openFollow(false)
				if err != nil {
					if ctx.Err() != nil {
						return nil
					}
					return err
				}
				reader = bufio.NewReader(f)
				continue
			case pathTruncated:
				// Same inode, but it shrank underneath us (copytruncate). Re-read from the top.
				log.Printf("agent: tail %q: truncation detected, re-reading", path)
				if _, serr := f.Seek(0, io.SeekStart); serr != nil {
					return serr
				}
				reader.Reset(f)
				offset = 0
				continue
			}
			// Genuinely idle: wait briefly for more data (or a rotation) to arrive.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(tailReopenPoll):
			}
		case rerr != nil:
			return rerr
		}
	}
}

type pathState int

const (
	pathSame      pathState = iota // still the same file, still growing (or idle)
	pathRotated                    // the path now names a different file (logrotate rename+create)
	pathTruncated                  // same file, but shorter than what we've read (copytruncate)
)

// classifyPath compares the file currently open (openInfo, and how far we've read: offset) against
// whatever the path names right now. A stat error (the file is briefly gone mid-rotation) is
// treated as "same" so we simply wait and re-check — the new file will be picked up next round.
func classifyPath(path string, openInfo os.FileInfo, offset int64) pathState {
	cur, err := os.Stat(path)
	if err != nil {
		return pathSame
	}
	if !os.SameFile(openInfo, cur) {
		return pathRotated
	}
	if cur.Size() < offset {
		return pathTruncated
	}
	return pathSame
}
