package agent

// Rootkit and local-anomaly checks, the portable half.
//
// The platform half (rootcheck_linux.go) does the walking and the syscalls. The decisions live
// here, with no build tag, for the same reason the macOS ps parser and the registry diff do: a
// test behind a linux tag would never run on a Windows developer machine, and the decisions are
// where a wrong answer costs something. A false positive here pages somebody at 3am about a
// rootkit that is not there, and a check that cries wolf gets switched off, which is worse than
// never having shipped it.

import (
	"sort"
	"strings"
)

// Rootcheck finding kinds.
const (
	// CheckHiddenProcess is a PID the kernel confirms is alive but which /proc does not list.
	// This is the signature of a readdir-hooking rootkit, and it is the highest-signal check
	// here: there is no benign explanation, unlike almost everything else a rootkit scanner
	// looks at.
	CheckHiddenProcess = "hidden_process"
	// CheckSUIDInTemp is a setuid or setgid executable in a directory where no package manager
	// puts one. A dropped suid shell in /tmp is the oldest privilege-escalation foothold there
	// is, and unlike a system suid binary it has no legitimate reason to exist.
	CheckSUIDInTemp = "suid_in_writable_dir"
	// CheckFileInDev is a regular file under /dev, which should hold device nodes. Rootkits have
	// stashed their configuration and stolen data there for decades because /dev is noisy,
	// usually excluded from backups, and nobody looks.
	CheckFileInDev = "file_in_dev"
)

// RootcheckFinding is one anomaly, shipped as a JSON line under the "rootcheck" dataset.
type RootcheckFinding struct {
	Check   string `json:"check"`
	Detail  string `json:"detail"`
	Path    string `json:"path,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

// suidSuspectDirs are the prefixes where a setuid binary is a finding rather than normal.
//
// An allow-list of suspicious places, not a block-list of safe ones. The system suid binaries
// (/usr/bin/sudo, /usr/bin/passwd, mount, ping, and a long tail that differs per distribution)
// are legitimate and numerous, so reporting everything outside a known-good list would produce
// pages of noise on any real host and the check would be muted within a day. These directories
// are world-writable or user-owned, and nothing a package manager installs lands in them.
var suidSuspectDirs = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
	"/home/",
	"/run/user/",
}

// suspiciousSUID reports whether a setuid/setgid executable at this path is worth an alert.
func suspiciousSUID(path string) bool {
	for _, d := range suidSuspectDirs {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

// devFileAllowed lists the regular files that legitimately live under /dev on a normal Linux
// system, so they are not reported every scan.
//
// Each of these is written by something ordinary: the kernel's own MAKEDEV bookkeeping, udev, or
// the shared-memory and container tooling that mounts tmpfs there. Everything else that is a
// plain file under /dev is worth a look.
var devFileAllowed = map[string]bool{
	"/dev/.udev":           true,
	"/dev/MAKEDEV":         true,
	"/dev/console":         true,
	"/dev/core":            true,
	"/dev/initctl":         true,
	"/dev/null":            true,
	"/dev/shm":             true,
	"/dev/zero":            true,
	"/dev/.initramfs":      true,
	"/dev/.mdadm":          true,
	"/dev/.systemd":        true,
	"/dev/.lxc":            true,
	"/dev/.lxd-mounts":     true,
	"/dev/log":             true,
	"/dev/full":            true,
	"/dev/random":          true,
	"/dev/urandom":         true,
	"/dev/ptmx":            true,
	"/dev/autofs":          true,
	"/dev/btrfs-control":   true,
	"/dev/fuse":            true,
	"/dev/kmsg":            true,
	"/dev/rfkill":          true,
	"/dev/vga_arbiter":     true,
	"/dev/userfaultfd":     true,
	"/dev/nvram":           true,
	"/dev/hwrng":           true,
	"/dev/vhost-net":       true,
	"/dev/vhost-vsock":     true,
	"/dev/vsock":           true,
	"/dev/cuse":            true,
	"/dev/net":             true,
	"/dev/mqueue":          true,
	"/dev/hugepages":       true,
	"/dev/pts":             true,
	"/dev/lightnvm":        true,
	"/dev/zfs":             true,
	"/dev/gpiochip0":       true,
	"/dev/watchdog":        true,
	"/dev/watchdog0":       true,
	"/dev/ppp":             true,
	"/dev/loop-control":    true,
	"/dev/uinput":          true,
	"/dev/dma_heap":        true,
	"/dev/udmabuf":         true,
	"/dev/nvme-fabrics":    true,
	"/dev/ecryptfs":        true,
	"/dev/snapshot":        true,
	"/dev/uhid":            true,
	"/dev/hpet":            true,
	"/dev/mcelog":          true,
	"/dev/cpu_dma_latency": true,
	"/dev/sgx_provision":   true,
	"/dev/sgx_vepc":        true,
	"/dev/tpm0":            true,
	"/dev/tpmrm0":          true,
}

// devPrefixAllowed are subtrees under /dev that hold ordinary files on normal systems, so their
// contents are not walked for this check at all.
var devPrefixAllowed = []string{
	"/dev/shm/",    // POSIX shared memory: every browser and database puts files here
	"/dev/mqueue/", // POSIX message queues appear as files
	"/dev/hugepages/",
	"/dev/.lxc/",
	"/dev/.lxd-mounts/",
	"/dev/lxd/",
	"/dev/.udev/",
	"/dev/.initramfs/",
}

// suspiciousDevFile reports whether a regular file at this path under /dev is worth an alert.
func suspiciousDevFile(path string) bool {
	if devFileAllowed[path] {
		return false
	}
	for _, p := range devPrefixAllowed {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	return true
}

// hiddenPIDs returns the PIDs that are alive according to the kernel but absent from the /proc
// listing, which is the shape a readdir-hooking rootkit leaves behind.
//
// listed is what reading /proc returned. alive is the kernel's answer for one PID, from a signal
// probe. Taking alive as a function keeps the comparison testable without spawning processes, and
// keeps this file free of syscalls.
//
// A PID that appears alive and unlisted is NOT reported on its own. Processes start and exit
// between the directory read and the probe constantly, so a single scan sees phantom disagreements
// all the time; reporting them would make this the noisiest check in the product rather than the
// most trustworthy one. The caller confirms across two passes, see confirmHidden.
func hiddenPIDs(listed map[int]bool, maxPID int, alive func(int) bool) []int {
	var out []int
	for pid := 1; pid <= maxPID; pid++ {
		if listed[pid] {
			continue
		}
		if alive(pid) {
			out = append(out, pid)
		}
	}
	return out
}

// confirmHidden keeps only the PIDs that looked hidden in BOTH passes and are still alive.
//
// This is what makes the hidden-process check usable. A process that exited between the /proc read
// and the probe looks hidden once and is gone by the next pass; a rootkit hiding a PID hides it
// every time. Requiring agreement across two independent scans costs one extra pass and removes
// essentially every false positive, which for a check whose alert says "rootkit" is the difference
// between shipping it and not.
func confirmHidden(first, second []int, alive func(int) bool) []int {
	inFirst := make(map[int]bool, len(first))
	for _, p := range first {
		inFirst[p] = true
	}
	var out []int
	for _, p := range second {
		if inFirst[p] && alive(p) {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}
