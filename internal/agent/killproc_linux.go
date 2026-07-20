//go:build linux

package agent

import (
	"os"
	"strconv"
	"syscall"
)

// procfsProcs reads process identity from /proc and terminates via signal.
type procfsProcs struct{}

// NewProcSource returns the Linux process source for the kill-switch.
func NewProcSource() ProcSource { return procfsProcs{} }

func (procfsProcs) Lookup(pid int) (ProcInfo, bool) {
	if pid <= 0 {
		return ProcInfo{}, false
	}
	dir := "/proc/" + strconv.Itoa(pid)
	raw, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return ProcInfo{}, false // gone, or not ours to see
	}
	comm, ppid, start, ok := parseProcStat(string(raw))
	if !ok {
		return ProcInfo{}, false
	}
	info := ProcInfo{PID: pid, Name: comm, Start: start}
	info.PPID, _ = strconv.Atoi(ppid)
	// The exe symlink can be unreadable (permissions, kernel thread) - that is not fatal, the
	// start time is the identity signal that matters.
	if exe, err := os.Readlink(dir + "/exe"); err == nil {
		info.Exe = exe
	}
	return info, true
}

// Kill sends SIGKILL rather than SIGTERM on purpose: a ransomware process handed SIGTERM can run
// a handler, and the only thing it would do with the extra time is finish encrypting or wipe its
// own traces. There is no graceful shutdown worth granting here.
func (procfsProcs) Kill(pid int) error {
	if pid <= 1 {
		return syscall.EPERM
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}
