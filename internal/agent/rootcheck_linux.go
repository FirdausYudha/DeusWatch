//go:build linux

package agent

// Rootkit and local-anomaly checks, the Linux half: the walking and the syscalls. Every decision
// about what counts as a finding is in rootcheck.go, which has no build tag and is tested.

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// rootcheckInterval is the default period between scans. Deliberately slow: these checks walk
// directories and probe thousands of PIDs, none of the things they look for appear and vanish
// within minutes, and an hourly scan that nobody disables is worth more than a minutely one that
// somebody turns off for the I/O.
const rootcheckInterval = 1 * time.Hour

// rootcheckMaxPID bounds the hidden-process probe. The kernel's pid_max is usually 4194304 on
// 64-bit, and probing four million PIDs every scan to find the handful a rootkit hides is not a
// trade worth making. /proc/sys/kernel/pid_max is read when available and capped here.
const rootcheckMaxPID = 65536

// rootcheckMaxWalk caps how many entries one directory walk will visit, so a scan cannot be
// turned into an I/O storm by a host with a pathological /tmp.
const rootcheckMaxWalk = 200000

// collectRootcheck is the "rootcheck" source collector.
func collectRootcheck(ctx context.Context, s Source, out chan<- Line) error {
	emit := func(f RootcheckFinding) bool {
		body, err := json.Marshal(f)
		if err != nil {
			return true
		}
		select {
		case out <- Line{Dataset: s.Dataset, Message: string(body)}:
			return true
		case <-ctx.Done():
			return false
		}
	}

	// Scan once at startup so a host that is already compromised does not stay quiet until the
	// first interval elapses, which with the default would be an hour.
	runRootcheck(ctx, emit)

	tick := time.NewTicker(s.scanInterval(rootcheckInterval))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			runRootcheck(ctx, emit)
		}
	}
}

// runRootcheck performs one pass of every check, stopping early if emit says the context is done.
func runRootcheck(ctx context.Context, emit func(RootcheckFinding) bool) {
	for _, f := range scanHiddenProcesses(ctx) {
		if !emit(f) {
			return
		}
	}
	for _, f := range scanSUID() {
		if !emit(f) {
			return
		}
	}
	for _, f := range scanDevFiles() {
		if !emit(f) {
			return
		}
	}
}

// pidAlive reports whether the kernel knows this PID.
//
// Signal 0 performs the permission and existence checks without delivering anything. ESRCH means
// no such process; EPERM means it exists but belongs to someone else, which still answers the
// question being asked, so EPERM counts as alive.
func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// listedPIDs reads the PIDs /proc admits to.
func listedPIDs() (map[int]bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}
	out := make(map[int]bool, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			out[pid] = true
		}
	}
	return out, nil
}

// maxPID reads the kernel's pid_max, capped at rootcheckMaxPID.
func maxPID() int {
	b, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return rootcheckMaxPID
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n <= 0 || n > rootcheckMaxPID {
		return rootcheckMaxPID
	}
	return n
}

// scanHiddenProcesses looks for PIDs the kernel confirms but /proc hides, confirming across two
// passes so a process that merely exited mid-scan is not reported as a rootkit.
func scanHiddenProcesses(ctx context.Context) []RootcheckFinding {
	max := maxPID()

	pass := func() []int {
		listed, err := listedPIDs()
		if err != nil {
			log.Printf("agent: rootcheck: %v", err)
			return nil
		}
		return hiddenPIDs(listed, max, pidAlive)
	}

	first := pass()
	if len(first) == 0 {
		return nil // the overwhelmingly common case: one /proc read and one probe sweep, then done
	}
	// Only reached when something looked hidden, so the second pass costs nothing on a clean host.
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(2 * time.Second):
	}
	confirmed := confirmHidden(first, pass(), pidAlive)

	out := make([]RootcheckFinding, 0, len(confirmed))
	for _, pid := range confirmed {
		out = append(out, RootcheckFinding{
			Check: CheckHiddenProcess,
			PID:   pid,
			Detail: fmt.Sprintf("PID %d is running according to the kernel but /proc does not list it, "+
				"confirmed over two passes; this is what a readdir-hooking rootkit looks like", pid),
		})
	}
	return out
}

// scanSUID walks the world-writable and user-owned directories looking for setuid/setgid
// executables, which nothing a package manager installs puts there.
func scanSUID() []RootcheckFinding {
	var out []RootcheckFinding
	visited := 0
	for _, root := range suidSuspectDirs {
		_ = filepath.WalkDir(strings.TrimSuffix(root, "/"), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // an unreadable subtree is not a finding, and not a reason to stop
			}
			if visited++; visited > rootcheckMaxWalk {
				return fs.SkipAll
			}
			if d.IsDir() {
				// /proc and /sys are not under these roots, but a user's home can hold a mount
				// point or a symlinked tree that loops. WalkDir does not follow symlinks, which
				// handles the loop; this skips the one directory that is always huge and never
				// interesting here.
				if d.Name() == ".cache" {
					return fs.SkipDir
				}
				return nil
			}
			fi, err := d.Info()
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			if fi.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0 {
				return nil
			}
			if !suspiciousSUID(p) {
				return nil
			}
			bits := "setuid"
			if fi.Mode()&os.ModeSetgid != 0 {
				bits = "setgid"
				if fi.Mode()&os.ModeSetuid != 0 {
					bits = "setuid+setgid"
				}
			}
			out = append(out, RootcheckFinding{
				Check: CheckSUIDInTemp,
				Path:  p,
				Detail: fmt.Sprintf("%s executable in a writable directory (mode %s); no package manager "+
					"puts one here, and a dropped suid shell is the oldest local privilege escalation there is",
					bits, fi.Mode().Perm().String()),
			})
			return nil
		})
	}
	return out
}

// scanDevFiles looks for regular files under /dev, which should hold device nodes.
func scanDevFiles() []RootcheckFinding {
	var out []RootcheckFinding
	visited := 0
	_ = filepath.WalkDir("/dev", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if visited++; visited > rootcheckMaxWalk {
			return fs.SkipAll
		}
		if d.IsDir() {
			if !suspiciousDevFile(p+"/") && p != "/dev" {
				return fs.SkipDir // an allowed subtree (shm, mqueue, hugepages) is not walked
			}
			return nil
		}
		fi, err := d.Info()
		if err != nil || !fi.Mode().IsRegular() {
			return nil // device nodes, sockets, symlinks and fifos are what belongs here
		}
		if !suspiciousDevFile(p) {
			return nil
		}
		out = append(out, RootcheckFinding{
			Check: CheckFileInDev,
			Path:  p,
			Detail: fmt.Sprintf("regular file under /dev (%d bytes); /dev holds device nodes, and rootkits "+
				"have stashed configuration and stolen data here for decades because nobody looks", fi.Size()),
		})
		return nil
	})
	return out
}
