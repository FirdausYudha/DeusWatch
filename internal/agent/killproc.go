package agent

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// Ransomware kill-switch: terminate the process that is encrypting files.
//
// This is the most destructive action DeusWatch can take on an endpoint, so the decision to kill
// is deliberately separated from the act of killing. Decide() below is pure and platform-free:
// every safety rule lives there and is unit-tested on any OS. The platform files only supply
// process introspection (killproc_linux.go / killproc_windows.go) and the raw signal.
//
// Two hazards drive the design:
//
//  1. PID REUSE. Between detection on the manager and execution on the agent, the original
//     process may exit and the OS may recycle its PID onto something innocent. Killing by PID
//     alone is therefore unsafe at any delay. We require the target to still match the identity
//     captured at detection time - the start time above all, since it is the only field an
//     attacker cannot trivially align and the only one that makes a recycled PID detectable.
//
//  2. PROTECTED PROCESSES. Killing init, a session leader, a core OS service, or the DeusWatch
//     agent itself turns a contained incident into an outage - or disables the very defense that
//     is responding. Those are refused outright, regardless of how confident the detection is.
//
// A refusal is never silently swallowed: each outcome is reported back and surfaced in the UI.

// ProcInfo is the live identity of a process, as read from the OS right before the kill.
type ProcInfo struct {
	PID   int
	PPID  int
	Name  string // short process name ("gpg", "svchost.exe")
	Exe   string // absolute executable path, when resolvable
	Start string // opaque platform token (Linux: starttime jiffies, Windows: creation time)
}

// KillTarget is what the manager asked us to kill, including the identity captured at detection
// time. The Want* fields are the anti-PID-reuse evidence.
type KillTarget struct {
	PID       int
	WantExe   string // executable path observed at detection
	WantName  string // process name observed at detection
	WantStart string // start-time token observed at detection - the strongest signal
}

// KillOutcome is the honest result of a kill request. Anything other than KillDone means the
// process is still running, and the UI must say so rather than implying containment.
type KillOutcome string

const (
	KillDone             KillOutcome = "killed"
	KillFailed           KillOutcome = "failed"
	KillSkippedProtected KillOutcome = "skipped_protected"
	KillSkippedGone      KillOutcome = "skipped_gone"
	KillSkippedMismatch  KillOutcome = "skipped_mismatch"
	KillSkippedNoID      KillOutcome = "skipped_no_identity"
)

// protectedNames are processes we refuse to kill on any platform. Killing one of these does more
// damage than most ransomware: the box loses its init, its login path, its container runtime, or
// its security agent.
//
// Deliberately NOT in this list: explorer.exe. Process injection into the user shell is a real
// ransomware technique (the user's own scenario 1), so protecting it would defeat the feature.
// Killing it logs the user out of their shell, which is recoverable; ransomware is not.
var protectedNames = map[string]bool{
	// Linux / Unix
	"init": true, "systemd": true, "kthreadd": true, "sshd": true, "dbus-daemon": true,
	"systemd-journald": true, "systemd-logind": true, "systemd-udevd": true, "auditd": true,
	"containerd": true, "dockerd": true, "launchd": true, "cron": true, "crond": true,
	// Windows
	"system": true, "smss.exe": true, "csrss.exe": true, "wininit.exe": true,
	"services.exe": true, "lsass.exe": true, "winlogon.exe": true, "svchost.exe": true,
	"lsm.exe": true, "spoolsv.exe": true, "memory compression": true,
	// DeusWatch itself - never let a response action disable the responder.
	"deuswatch-agent": true, "deuswatch-agent.exe": true, "deuswatch": true,
}

// normalizeProcName lowercases and strips any directory part, so "/usr/lib/systemd/systemd" and
// "C:\\Windows\\System32\\lsass.exe" both reduce to the name we match on.
func normalizeProcName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// IsProtected reports whether p must never be killed, with a human reason for the audit trail.
// selfPID/selfPPID are the agent's own pid and parent, passed in so this stays pure.
func IsProtected(p ProcInfo, selfPID, selfPPID int, extraNames []string) (bool, string) {
	if p.PID <= 1 {
		return true, "pid <= 1 (init/kernel)"
	}
	if p.PID == selfPID {
		return true, "the DeusWatch agent itself"
	}
	if selfPPID > 1 && p.PID == selfPPID {
		return true, "the DeusWatch agent's parent (service manager)"
	}
	name := normalizeProcName(p.Name)
	exeName := normalizeProcName(p.Exe)
	for _, n := range []string{name, exeName} {
		if n != "" && protectedNames[n] {
			return true, "protected system process " + n
		}
	}
	for _, e := range extraNames {
		e = normalizeProcName(e)
		if e == "" {
			continue
		}
		if e == name || e == exeName {
			return true, "operator-protected process " + e
		}
	}
	return false, ""
}

// identityMatches compares the live process against the identity captured at detection time.
// Start time is authoritative when both sides have it: a recycled PID cannot reproduce it.
// Exe/name are corroborating only - they are trivially shared by many processes.
func identityMatches(t KillTarget, p ProcInfo) (bool, string) {
	if t.WantStart != "" && p.Start != "" {
		if t.WantStart != p.Start {
			return false, fmt.Sprintf("start time differs (want %s, live %s) - the PID was recycled", t.WantStart, p.Start)
		}
		return true, ""
	}
	// No start time on one side: fall back to the executable path, which at least rules out a
	// PID recycled onto a different program.
	if t.WantExe != "" && p.Exe != "" {
		if !samePath(t.WantExe, p.Exe) {
			return false, fmt.Sprintf("executable differs (want %s, live %s)", t.WantExe, p.Exe)
		}
		return true, ""
	}
	if t.WantName != "" && p.Name != "" {
		if normalizeProcName(t.WantName) != normalizeProcName(p.Name) {
			return false, fmt.Sprintf("process name differs (want %s, live %s)", t.WantName, p.Name)
		}
		return true, ""
	}
	return false, "no identity evidence to verify the PID against"
}

// samePath compares executable paths case-insensitively on the name and cleanly on the rest,
// tolerating the separator differences between how audit and /proc report a path.
func samePath(a, b string) bool {
	norm := func(s string) string {
		s = strings.ReplaceAll(strings.TrimSpace(s), `\`, "/")
		s = path.Clean(s)
		if filepath.Separator == '\\' {
			s = strings.ToLower(s)
		}
		return s
	}
	return norm(a) == norm(b)
}

// Decide is the whole safety policy in one pure function: given what we were asked to kill and
// what is actually running under that PID right now, should we kill it?
//
// Order matters. "Gone" is checked first (nothing to do), then protection (never kill, even with
// perfect evidence), then identity (never kill the wrong process). Only a request that clears all
// three is authorized.
func Decide(t KillTarget, live ProcInfo, found bool, selfPID, selfPPID int, extraProtected []string) (KillOutcome, string) {
	if t.PID <= 0 {
		return KillSkippedNoID, "no pid supplied"
	}
	if !found {
		// Already exited - the desired end state, reported honestly rather than as a kill.
		return KillSkippedGone, "process is no longer running"
	}
	if prot, why := IsProtected(live, selfPID, selfPPID, extraProtected); prot {
		return KillSkippedProtected, why
	}
	if t.WantStart == "" && t.WantExe == "" && t.WantName == "" {
		return KillSkippedNoID, "no identity captured at detection - refusing to kill by pid alone"
	}
	if ok, why := identityMatches(t, live); !ok {
		return KillSkippedMismatch, why
	}
	return KillDone, ""
}

// KillSwitch executes a verified kill. src supplies live process introspection for the platform.
// It returns the outcome and a reason suitable for the audit trail; the caller reports both to
// the manager verbatim. A nil src (unsupported platform) is an honest failure, not a silent skip.
func KillSwitch(t KillTarget, src ProcSource, selfPID, selfPPID int, extraProtected []string) (KillOutcome, string) {
	if src == nil {
		return KillFailed, "process control is not supported on this platform"
	}
	live, found := src.Lookup(t.PID)
	outcome, why := Decide(t, live, found, selfPID, selfPPID, extraProtected)
	if outcome != KillDone {
		return outcome, why
	}
	if err := src.Kill(t.PID); err != nil {
		return KillFailed, err.Error()
	}
	// Re-check: a kill that returns nil but leaves the process alive (uninterruptible sleep,
	// permission quirks, a shim) must not be reported as success.
	if after, still := src.Lookup(t.PID); still && after.Start == live.Start {
		return KillFailed, "kill issued but the process is still running"
	}
	return KillDone, fmt.Sprintf("killed pid %d (%s)", t.PID, live.Name)
}

// ProcSource is the platform's process introspection + termination.
type ProcSource interface {
	Lookup(pid int) (ProcInfo, bool)
	Kill(pid int) error
}
