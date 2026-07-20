//go:build windows

package agent

import (
	"strconv"

	"golang.org/x/sys/windows"
)

// winProcs reads process identity via the Win32 API and terminates with TerminateProcess.
type winProcs struct{}

// NewProcSource returns the Windows process source for the kill-switch.
func NewProcSource() ProcSource { return winProcs{} }

func (winProcs) Lookup(pid int) (ProcInfo, bool) {
	if pid <= 0 {
		return ProcInfo{}, false
	}
	// QUERY_LIMITED_INFORMATION is the least privilege that still yields the image name and the
	// creation time, and unlike QUERY_INFORMATION it works against processes at a higher
	// integrity level - so a protected process is correctly identified as protected rather than
	// looking like it is gone.
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ProcInfo{}, false
	}
	defer windows.CloseHandle(h)

	info := ProcInfo{PID: pid}

	// Creation time is the anti-PID-reuse identity: Windows recycles PIDs aggressively.
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err == nil {
		info.Start = strconv.FormatInt(creation.Nanoseconds(), 10)
	}

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err == nil {
		info.Exe = windows.UTF16ToString(buf[:size])
		info.Name = normalizeProcName(info.Exe)
	}
	// A process we cannot identify at all must not be treated as a verified target; Decide()
	// refuses it, but returning found=true keeps that refusal honest ("mismatch") rather than
	// silently reporting the process as gone.
	return info, true
}

// Kill terminates immediately. As on Linux there is no graceful path worth offering ransomware.
func (winProcs) Kill(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}
