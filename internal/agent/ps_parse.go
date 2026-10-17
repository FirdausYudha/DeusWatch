// Parsing of macOS `ps` output. Deliberately NOT behind a darwin build tag: the exec call in
// process_snapshot_darwin.go is platform specific, this parser is not, and a test behind a darwin
// tag would never run in CI. The risky part of this collector is the parsing, so the parsing is
// the part that has to be testable on the build machine.

package agent

import (
	"strconv"
	"strings"
	"time"
)

// parsePSLine turns one `ps` row into a snapshot, or nil when the row is not one.
//
// lstart is five whitespace-separated tokens of its own ("Mon Jan  1 00:00:00 2026"), so the
// layout is: pid ppid user rss <5 tokens of lstart> command...
func parsePSLine(line string) *ProcessSnapshot {
	f := strings.Fields(line)
	const lead = 4 // pid ppid user rss
	const lstartTokens = 5
	if len(f) < lead+lstartTokens+1 {
		return nil
	}
	pid, err := strconv.Atoi(f[0])
	if err != nil {
		return nil // the header row, or a continuation line
	}
	ppid, _ := strconv.Atoi(f[1])
	rssKB, _ := strconv.ParseUint(f[3], 10, 64)

	start, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006",
		strings.Join(f[lead:lead+lstartTokens], " "), time.Local)
	if err != nil {
		start = time.Time{} // an unreadable start time is not a reason to drop the process
	}

	// Everything from here on is the executable path, which may contain spaces. Rejoining the
	// remaining fields would collapse runs of spaces inside a path, so take the tail of the
	// original line instead. The offset is counted field by field rather than searched for: a
	// search for the command token would match an earlier occurrence of the same text, and
	// "/usr/bin/ps" run by a user whose name appears in its own path is not a hypothetical.
	off := fieldOffset(line, lead+lstartTokens)
	if off < 0 {
		return nil
	}
	path := strings.TrimSpace(line[off:])

	return &ProcessSnapshot{
		PID:       pid,
		ParentPID: ppid,
		User:      f[2],
		Name:      pathBase(path),
		Cmdline:   path,
		Path:      path,
		StartTime: start,
		MemoryMB:  rssKB / 1024,
		FileHash:  getOrComputeHash(path),
	}
}

// fieldOffset returns the byte offset at which whitespace-separated field n (0-based) starts, or
// -1 when the line has fewer fields.
func fieldOffset(line string, n int) int {
	i := 0
	for f := 0; ; f++ {
		for i < len(line) && isSpace(line[i]) {
			i++
		}
		if i >= len(line) {
			return -1
		}
		if f == n {
			return i
		}
		for i < len(line) && !isSpace(line[i]) {
			i++
		}
	}
}

func isSpace(c byte) bool { return c == ' ' || c == '	' }

// pathBase is filepath.Base for a path that is always a slash path on macOS, and which returns ""
// rather than "." for an empty input so an unknown executable does not show up as a process
// literally named ".".
func pathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
