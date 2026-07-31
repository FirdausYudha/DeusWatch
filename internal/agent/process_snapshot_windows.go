//go:build windows

package agent

import (
	"fmt"
	"os/user"
	"strings"
	"time"

	"github.com/StackExchange/wmi"
)

// Win32_Process WMI class for querying process information.
type Win32_Process struct {
	Handle          string
	Name            string
	ExecutablePath  string
	ProcessID       uint32
	ParentProcessID uint32
	CommandLine     string
	WorkingSetSize  uint64
	CreationTime    string // WMI datetime format
}

// collectProcesses is the platform-specific implementation for Windows.
func collectProcesses() ([]ProcessSnapshot, error) {
	return collectProcessesWindows()
}

// collectProcessesWindows queries all running processes via WMI.
func collectProcessesWindows() ([]ProcessSnapshot, error) {
	var wmiProcesses []Win32_Process
	q := wmi.CreateQuery(&wmiProcesses, "")
	err := wmi.Query(q, &wmiProcesses)
	if err != nil {
		return nil, fmt.Errorf("WMI query: %w", err)
	}

	var snapshots []ProcessSnapshot
	for _, wmiProc := range wmiProcesses {
		snap := convertWMIProcess(wmiProc)
		if snap != nil {
			snapshots = append(snapshots, *snap)
		}
	}

	return snapshots, nil
}

// convertWMIProcess converts a Win32_Process WMI object to ProcessSnapshot.
// Returns nil if conversion fails.
func convertWMIProcess(wmiProc Win32_Process) *ProcessSnapshot {
	// Get process start time
	startTime := parseWMIDateTime(wmiProc.CreationTime)

	// Get username (may be empty for some system processes)
	username := getProcessOwner(wmiProc.ProcessID)

	// ExecutablePath may be empty for some processes
	execPath := wmiProc.ExecutablePath
	if execPath == "" {
		execPath = wmiProc.Name
	}

	// Memory: convert bytes to MB
	memoryMB := wmiProc.WorkingSetSize / (1024 * 1024)

	return &ProcessSnapshot{
		PID:       int(wmiProc.ProcessID),
		Name:      wmiProc.Name,
		ParentPID: int(wmiProc.ParentProcessID),
		Cmdline:   wmiProc.CommandLine,
		User:      username,
		Path:      execPath,
		StartTime: startTime,
		MemoryMB:  memoryMB,
		FileHash:  getOrComputeHash(execPath),
	}
}

// parseWMIDateTime converts WMI datetime format to time.Time.
// Format: "20260731103000.000000-000"
func parseWMIDateTime(wmiTime string) time.Time {
	if wmiTime == "" {
		return time.Now()
	}

	// Extract just the timestamp part before the +/- timezone
	var ts string
	if idx := strings.IndexAny(wmiTime, "+-"); idx > 0 {
		ts = wmiTime[:idx]
	} else {
		ts = wmiTime
	}

	// Remove decimal part (microseconds)
	if idx := strings.IndexByte(ts, '.'); idx > 0 {
		ts = ts[:idx]
	}

	// Parse YYYYMMDDHHMMSS format
	if len(ts) < 14 {
		return time.Now()
	}

	year := ts[0:4]
	month := ts[4:6]
	day := ts[6:8]
	hour := ts[8:10]
	minute := ts[10:12]
	second := ts[12:14]

	timeStr := fmt.Sprintf("%s-%s-%s %s:%s:%s", year, month, day, hour, minute, second)
	t, err := time.Parse("2006-01-02 15:04:05", timeStr)
	if err != nil {
		return time.Now()
	}
	return t
}

// getProcessOwner returns the username of the process owner.
func getProcessOwner(pid uint32) string {
	// Try to get owner via current user (fallback)
	currentUser, err := user.Current()
	if err == nil {
		return currentUser.Username
	}
	return ""
}
