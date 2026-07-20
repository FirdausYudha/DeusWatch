package agent

import "strings"

// parseProcStat extracts ppid, comm and starttime from the contents of /proc/<pid>/stat.
//
// Kept portable and pure (no file IO, no build tag) so the parsing - the part that is easy to get
// wrong - is unit-tested on every platform, not only on Linux.
//
// The format is deceptively hostile: field 2 is the process name in parentheses and may itself
// contain spaces AND parentheses (a process can rename itself to ") evil ("). Splitting the line
// on whitespace is therefore wrong. The only reliable anchor is the LAST ')' in the line;
// everything after it is fixed-width, space-separated fields starting at field 3 (state).
//
// Field numbers are 1-based per proc(5): 1=pid 2=comm 3=state 4=ppid ... 22=starttime.
func parseProcStat(s string) (comm string, ppid string, starttime string, ok bool) {
	open := strings.IndexByte(s, '(')
	close := strings.LastIndexByte(s, ')')
	if open < 0 || close < 0 || close < open {
		return "", "", "", false
	}
	comm = s[open+1 : close]

	rest := strings.Fields(s[close+1:])
	// rest[0] is field 3 (state), so field N lives at rest[N-3].
	const ppidIdx, startIdx = 4 - 3, 22 - 3
	if len(rest) <= startIdx {
		return "", "", "", false
	}
	return comm, rest[ppidIdx], rest[startIdx], true
}
