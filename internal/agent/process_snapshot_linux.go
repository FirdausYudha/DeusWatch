//go:build linux

package agent

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// collectProcesses is the platform-specific implementation for Linux.
func collectProcesses() ([]ProcessSnapshot, error) {
	return collectProcessesLinux()
}

// collectProcessesLinux reads all processes from /proc and builds ProcessSnapshot list.
func collectProcessesLinux() ([]ProcessSnapshot, error) {
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}

	var snapshots []ProcessSnapshot
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// PID directories are numeric
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // skip non-numeric entries
		}

		// Extract process info; skip if any step fails (process may have exited)
		snap := readProcessInfoLinux(pid)
		if snap == nil {
			continue
		}

		snapshots = append(snapshots, *snap)
	}

	return snapshots, nil
}

// readProcessInfoLinux extracts one process's snapshot from /proc/[pid]/*.
// Returns nil if the process vanishes or data cannot be read.
func readProcessInfoLinux(pid int) *ProcessSnapshot {
	baseDir := fmt.Sprintf("/proc/%d", pid)

	// Read stat file for PID, name, parent PID, start time
	stat, err := readStat(baseDir)
	if err != nil {
		return nil
	}

	// Read cmdline
	cmdline := readCmdline(baseDir)

	// Read status for UID/GID
	userID := readUID(baseDir)

	// Get username from UID
	username := uidToUsername(userID)

	// Get executable path from exe symlink
	execPath := readExePath(baseDir)

	// Get memory usage in MB
	memoryMB := readMemory(baseDir)

	return &ProcessSnapshot{
		PID:       pid,
		Name:      stat.Name,
		ParentPID: stat.ParentPID,
		Cmdline:   cmdline,
		User:      username,
		Path:      execPath,
		StartTime: stat.StartTime,
		MemoryMB:  memoryMB,
		FileHash:  getOrComputeHash(execPath),
	}
}

// statInfo holds parsed /proc/[pid]/stat data.
type statInfo struct {
	Name      string
	ParentPID int
	StartTime time.Time
}

// readStat parses /proc/[pid]/stat for name, parent PID, and start time.
func readStat(baseDir string) (*statInfo, error) {
	data, err := os.ReadFile(filepath.Join(baseDir, "stat"))
	if err != nil {
		return nil, err
	}

	line := strings.TrimSpace(string(data))
	if line == "" {
		return nil, fmt.Errorf("empty stat")
	}

	// Format: pid (name) state ppid ...
	// The name is in parens and may contain spaces
	openIdx := strings.IndexByte(line, '(')
	closeIdx := strings.LastIndexByte(line, ')')
	if openIdx < 0 || closeIdx < 0 || closeIdx < openIdx {
		return nil, fmt.Errorf("malformed stat")
	}

	name := line[openIdx+1 : closeIdx]

	// Everything after ) is space-separated fields
	fields := strings.Fields(line[closeIdx+1:])
	if len(fields) < 20 {
		return nil, fmt.Errorf("too few stat fields")
	}

	// field[0] = state (ignored)
	// field[1] = ppid (parent PID)
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, err
	}

	// field[19] = starttime (in jiffies since boot)
	startJiffies, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return nil, err
	}

	// Convert jiffies to time (rough approximation: assume 100 jiffies/sec)
	bootTime := getBootTime()
	startTime := bootTime.Add(time.Duration(startJiffies*10) * time.Millisecond)

	return &statInfo{
		Name:      name,
		ParentPID: ppid,
		StartTime: startTime,
	}, nil
}

// bootTime is cached system boot time
var (
	bootTime     time.Time
	bootTimeOnce sync.Once
)

// getBootTime returns system boot time by parsing /proc/uptime.
func getBootTime() time.Time {
	bootTimeOnce.Do(func() {
		// /proc/uptime contains: uptime_seconds idle_time_seconds
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			bootTime = time.Now()
			return
		}

		fields := strings.Fields(string(data))
		if len(fields) < 1 {
			bootTime = time.Now()
			return
		}

		uptimeSec, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			bootTime = time.Now()
			return
		}

		bootTime = time.Now().Add(-time.Duration(uptimeSec) * time.Second)
	})
	return bootTime
}

// readCmdline reads /proc/[pid]/cmdline (null-separated args, joined with space).
func readCmdline(baseDir string) string {
	data, err := os.ReadFile(filepath.Join(baseDir, "cmdline"))
	if err != nil {
		return ""
	}

	// cmdline is null-terminated; split and join with space
	cmdlineStr := strings.Trim(string(data), "\x00")
	args := strings.Split(cmdlineStr, "\x00")
	return strings.Join(args, " ")
}

// readUID reads /proc/[pid]/status for the UID.
func readUID(baseDir string) string {
	data, err := os.ReadFile(filepath.Join(baseDir, "status"))
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			// Format: Uid:    1000    1000    1000    1000
			fields := strings.Fields(line)
			if len(fields) > 1 {
				return fields[1] // Real UID
			}
		}
	}
	return ""
}

// uidToUsername converts numeric UID to username.
func uidToUsername(uid string) string {
	if uid == "" {
		return ""
	}

	u, err := user.LookupId(uid)
	if err != nil {
		return uid // fallback to numeric UID
	}
	return u.Username
}

// readExePath reads the executable path from /proc/[pid]/exe symlink.
func readExePath(baseDir string) string {
	exePath := filepath.Join(baseDir, "exe")
	path, err := os.Readlink(exePath)
	if err != nil {
		return ""
	}
	return path
}

// readMemory reads RSS (resident set size) from /proc/[pid]/status in MB.
func readMemory(baseDir string) uint64 {
	data, err := os.ReadFile(filepath.Join(baseDir, "status"))
	if err != nil {
		return 0
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			// Format: VmRSS:    12345 kB
			fields := strings.Fields(line)
			if len(fields) > 1 {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err == nil {
					return kb / 1024 // Convert KB to MB
				}
			}
		}
	}
	return 0
}
