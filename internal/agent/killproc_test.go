package agent

import (
	"errors"
	"testing"
)

// fakeProcs is an in-memory ProcSource so the kill path is testable on any OS.
type fakeProcs struct {
	procs    map[int]ProcInfo
	killed   []int
	killErr  error
	survives bool // simulate a kill that returns nil but leaves the process running
}

func (f *fakeProcs) Lookup(pid int) (ProcInfo, bool) {
	p, ok := f.procs[pid]
	return p, ok
}

func (f *fakeProcs) Kill(pid int) error {
	f.killed = append(f.killed, pid)
	if f.killErr != nil {
		return f.killErr
	}
	if !f.survives {
		delete(f.procs, pid)
	}
	return nil
}

const (
	selfPID  = 500
	selfPPID = 1
)

// TestKillSwitchTerminatesVerifiedRansomware is the happy path: identity captured at detection
// still matches the live process, nothing protected, so the process dies.
func TestKillSwitchTerminatesVerifiedRansomware(t *testing.T) {
	f := &fakeProcs{procs: map[int]ProcInfo{
		4242: {PID: 4242, PPID: 900, Name: "cryptor", Exe: "/tmp/.x/cryptor", Start: "88123"},
	}}
	target := KillTarget{PID: 4242, WantExe: "/tmp/.x/cryptor", WantName: "cryptor", WantStart: "88123"}

	got, why := KillSwitch(target, f, selfPID, selfPPID, nil)
	if got != KillDone {
		t.Fatalf("expected the ransomware to be killed, got %s (%s)", got, why)
	}
	if len(f.killed) != 1 || f.killed[0] != 4242 {
		t.Fatalf("expected exactly pid 4242 to be killed, got %v", f.killed)
	}
}

// TestKillSwitchRefusesRecycledPID is the single most important test in this file. The process we
// were told to kill has exited and the OS handed its PID to something else. Killing by PID alone
// would take out an innocent process; the start-time check must catch it.
func TestKillSwitchRefusesRecycledPID(t *testing.T) {
	f := &fakeProcs{procs: map[int]ProcInfo{
		// Same PID, but this is postgres now - different start time.
		4242: {PID: 4242, PPID: 900, Name: "postgres", Exe: "/usr/bin/postgres", Start: "99999"},
	}}
	target := KillTarget{PID: 4242, WantExe: "/tmp/.x/cryptor", WantName: "cryptor", WantStart: "88123"}

	got, why := KillSwitch(target, f, selfPID, selfPPID, nil)
	if got != KillSkippedMismatch {
		t.Fatalf("a recycled pid must NOT be killed, got %s (%s)", got, why)
	}
	if len(f.killed) != 0 {
		t.Fatalf("nothing may be killed on identity mismatch, killed %v", f.killed)
	}
}

// TestKillSwitchRefusesProtectedProcesses covers the outage hazard: even a confident detection
// must never take out init, a core OS service, or the agent itself.
func TestKillSwitchRefusesProtectedProcesses(t *testing.T) {
	cases := []struct {
		name string
		proc ProcInfo
	}{
		{"init", ProcInfo{PID: 1, Name: "systemd", Exe: "/usr/lib/systemd/systemd", Start: "1"}},
		{"sshd", ProcInfo{PID: 800, Name: "sshd", Exe: "/usr/sbin/sshd", Start: "2"}},
		{"lsass", ProcInfo{PID: 801, Name: "lsass.exe", Exe: `C:\Windows\System32\lsass.exe`, Start: "3"}},
		{"the agent itself", ProcInfo{PID: selfPID, Name: "deuswatch-agent", Exe: "/usr/bin/deuswatch-agent", Start: "4"}},
		{"the agent's service manager", ProcInfo{PID: 7, Name: "whatever", Exe: "/x", Start: "5"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeProcs{procs: map[int]ProcInfo{tc.proc.PID: tc.proc}}
			// Identity matches perfectly - protection must still win.
			target := KillTarget{PID: tc.proc.PID, WantExe: tc.proc.Exe, WantName: tc.proc.Name, WantStart: tc.proc.Start}
			ppid := selfPPID
			if tc.name == "the agent's service manager" {
				ppid = 7
			}
			got, why := KillSwitch(target, f, selfPID, ppid, nil)
			if got != KillSkippedProtected {
				t.Fatalf("%s must be protected, got %s (%s)", tc.name, got, why)
			}
			if len(f.killed) != 0 {
				t.Fatalf("a protected process must never be killed, killed %v", f.killed)
			}
			if why == "" {
				t.Fatal("a refusal must carry a reason for the audit trail")
			}
		})
	}
}

// TestKillSwitchRefusesKillByPIDAlone: with no identity captured at detection there is no way to
// tell the target from a recycled PID, so the only safe answer is to refuse.
func TestKillSwitchRefusesKillByPIDAlone(t *testing.T) {
	f := &fakeProcs{procs: map[int]ProcInfo{
		4242: {PID: 4242, Name: "cryptor", Exe: "/tmp/cryptor", Start: "88123"},
	}}
	got, why := KillSwitch(KillTarget{PID: 4242}, f, selfPID, selfPPID, nil)
	if got != KillSkippedNoID {
		t.Fatalf("killing on a bare pid must be refused, got %s (%s)", got, why)
	}
	if len(f.killed) != 0 {
		t.Fatalf("nothing may be killed without identity, killed %v", f.killed)
	}
}

// TestKillSwitchOperatorProtectedList proves an admin can shield business-critical processes that
// DeusWatch cannot know about (an ERP, a database, a trading process).
func TestKillSwitchOperatorProtectedList(t *testing.T) {
	f := &fakeProcs{procs: map[int]ProcInfo{
		4242: {PID: 4242, Name: "sapstartsrv", Exe: "/usr/sap/sapstartsrv", Start: "88123"},
	}}
	target := KillTarget{PID: 4242, WantName: "sapstartsrv", WantStart: "88123"}
	got, why := KillSwitch(target, f, selfPID, selfPPID, []string{"SAPStartSrv", "oracle"})
	if got != KillSkippedProtected {
		t.Fatalf("operator-protected process must be refused, got %s (%s)", got, why)
	}
}

// TestKillSwitchAlreadyGone: the process exited on its own. That is the desired end state, but it
// must be reported as "gone", never as a kill we performed.
func TestKillSwitchAlreadyGone(t *testing.T) {
	f := &fakeProcs{procs: map[int]ProcInfo{}}
	target := KillTarget{PID: 4242, WantStart: "88123"}
	got, _ := KillSwitch(target, f, selfPID, selfPPID, nil)
	if got != KillSkippedGone {
		t.Fatalf("expected skipped_gone, got %s", got)
	}
	if len(f.killed) != 0 {
		t.Fatalf("must not kill a pid that is gone, killed %v", f.killed)
	}
}

// TestKillSwitchReportsFailureHonestly covers the two ways a kill can fail. Neither may be
// reported as success - the operator has to know the ransomware is still running.
func TestKillSwitchReportsFailureHonestly(t *testing.T) {
	target := KillTarget{PID: 4242, WantStart: "88123"}
	live := ProcInfo{PID: 4242, Name: "cryptor", Exe: "/tmp/cryptor", Start: "88123"}

	t.Run("kill returns an error", func(t *testing.T) {
		f := &fakeProcs{procs: map[int]ProcInfo{4242: live}, killErr: errors.New("operation not permitted")}
		got, why := KillSwitch(target, f, selfPID, selfPPID, nil)
		if got != KillFailed {
			t.Fatalf("expected failed, got %s", got)
		}
		if why == "" {
			t.Fatal("failure must explain itself")
		}
	})

	t.Run("kill succeeds but the process survives", func(t *testing.T) {
		f := &fakeProcs{procs: map[int]ProcInfo{4242: live}, survives: true}
		got, why := KillSwitch(target, f, selfPID, selfPPID, nil)
		if got != KillFailed {
			t.Fatalf("a surviving process must be reported as failed, got %s (%s)", got, why)
		}
	})
}

// TestKillSwitchUnsupportedPlatform: no process control compiled in must be an honest failure,
// not a silent success that makes the UI claim containment.
func TestKillSwitchUnsupportedPlatform(t *testing.T) {
	got, why := KillSwitch(KillTarget{PID: 4242, WantStart: "1"}, nil, selfPID, selfPPID, nil)
	if got != KillFailed || why == "" {
		t.Fatalf("unsupported platform must fail loudly, got %s (%s)", got, why)
	}
}

// TestIdentityFallsBackToExeWhenStartTimeUnavailable: not every platform/source yields a start
// time. The exe path is weaker but still rules out a PID recycled onto a different program.
func TestIdentityFallsBackToExeWhenStartTimeUnavailable(t *testing.T) {
	f := &fakeProcs{procs: map[int]ProcInfo{
		4242: {PID: 4242, Name: "cryptor", Exe: "/tmp/.x/cryptor"},
	}}
	ok := KillTarget{PID: 4242, WantExe: "/tmp/.x/./cryptor"} // same path, needs cleaning
	if got, why := KillSwitch(ok, f, selfPID, selfPPID, nil); got != KillDone {
		t.Fatalf("matching exe should authorize the kill, got %s (%s)", got, why)
	}

	f2 := &fakeProcs{procs: map[int]ProcInfo{
		4242: {PID: 4242, Name: "postgres", Exe: "/usr/bin/postgres"},
	}}
	bad := KillTarget{PID: 4242, WantExe: "/tmp/.x/cryptor"}
	if got, _ := KillSwitch(bad, f2, selfPID, selfPPID, nil); got != KillSkippedMismatch {
		t.Fatalf("differing exe must refuse, got %s", got)
	}
}
