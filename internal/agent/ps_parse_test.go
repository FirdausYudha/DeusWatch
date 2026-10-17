package agent

import "testing"

// TestParsePSLine covers the rows that break a naive split: a path containing spaces, a path that
// contains the user name, the header, and short rows.
func TestParsePSLine(t *testing.T) {
	for _, tc := range []struct {
		name    string
		line    string
		wantNil bool
		pid     int
		ppid    int
		user    string
		path    string
		base    string
		memMB   uint64
	}{
		{
			name: "ordinary row",
			line: "  501     1 root        8192 Mon Jan  1 00:00:00 2026 /usr/sbin/syslogd",
			pid:  501, ppid: 1, user: "root", path: "/usr/sbin/syslogd", base: "syslogd", memMB: 8,
		},
		{
			name: "path with spaces is kept whole",
			line: " 1234   501 alice      65536 Tue Feb 10 13:45:01 2026 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			pid:  1234, ppid: 501, user: "alice",
			path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			base: "Google Chrome", memMB: 64,
		},
		{
			// The reason the offset is counted rather than searched: the command token "ps"
			// also occurs inside the user name earlier in the line.
			name: "command text also appears earlier in the line",
			line: " 99 1 psops 1024 Wed Mar 4 09:00:00 2026 /bin/ps",
			pid:  99, ppid: 1, user: "psops", path: "/bin/ps", base: "ps", memMB: 1,
		},
		{name: "header", line: "  PID  PPID USER      RSS STARTED COMMAND", wantNil: true},
		{name: "blank", line: "", wantNil: true},
		{name: "truncated", line: "  501     1 root 8192", wantNil: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parsePSLine(tc.line)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("parsed a row that is not one: %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("row did not parse")
			}
			if got.PID != tc.pid || got.ParentPID != tc.ppid {
				t.Errorf("pid/ppid = %d/%d, want %d/%d", got.PID, got.ParentPID, tc.pid, tc.ppid)
			}
			if got.User != tc.user {
				t.Errorf("user = %q, want %q", got.User, tc.user)
			}
			if got.Path != tc.path {
				t.Errorf("path = %q, want %q", got.Path, tc.path)
			}
			if got.Name != tc.base {
				t.Errorf("name = %q, want %q", got.Name, tc.base)
			}
			if got.MemoryMB != tc.memMB {
				t.Errorf("memory = %d MB, want %d", got.MemoryMB, tc.memMB)
			}
			if got.StartTime.IsZero() {
				t.Error("start time did not parse")
			}
		})
	}
}

func TestFieldOffset(t *testing.T) {
	const line = "  a bb   ccc d"
	for n, want := range map[int]int{0: 2, 1: 4, 2: 9, 3: 13, 4: -1} {
		if got := fieldOffset(line, n); got != want {
			t.Errorf("fieldOffset(%d) = %d, want %d", n, got, want)
		}
	}
}
