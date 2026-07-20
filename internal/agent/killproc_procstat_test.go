package agent

import "testing"

// TestParseProcStat covers the trap in /proc/<pid>/stat: the process name is attacker-controlled
// and can contain spaces and parentheses, so naive whitespace splitting misreads every field
// after it - including the start time the kill-switch relies on to detect a recycled PID.
func TestParseProcStat(t *testing.T) {
	cases := []struct {
		name              string
		line              string
		comm, ppid, start string
		ok                bool
	}{
		{
			name: "ordinary process",
			line: "4242 (cryptor) R 900 4242 900 0 -1 4194304 120 0 0 0 5 2 0 0 20 0 1 0 88123 12345 6 18446744073709551615",
			comm: "cryptor", ppid: "900", start: "88123", ok: true,
		},
		{
			// A process CAN rename itself to contain parens and spaces. This is the case that
			// breaks naive parsers and would make us kill the wrong pid.
			name: "adversarial comm with spaces and parens",
			line: "4242 (evil ) proc (x) R 900 4242 900 0 -1 4194304 120 0 0 0 5 2 0 0 20 0 1 0 88123 12345 6 1",
			comm: "evil ) proc (x", ppid: "900", start: "88123", ok: true,
		},
		{
			name: "truncated line is rejected rather than guessed",
			line: "4242 (cryptor) R 900 4242",
			ok:   false,
		},
		{
			name: "garbage is rejected",
			line: "not a stat line",
			ok:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			comm, ppid, start, ok := parseProcStat(tc.line)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !tc.ok {
				return
			}
			if comm != tc.comm || ppid != tc.ppid || start != tc.start {
				t.Fatalf("got comm=%q ppid=%q start=%q; want comm=%q ppid=%q start=%q",
					comm, ppid, start, tc.comm, tc.ppid, tc.start)
			}
		})
	}
}
