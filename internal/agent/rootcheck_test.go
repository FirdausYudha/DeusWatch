package agent

import (
	"reflect"
	"testing"
)

// TestHiddenPIDs is the core of the highest-signal check: the kernel says a PID is alive, /proc
// does not list it.
func TestHiddenPIDs(t *testing.T) {
	listed := map[int]bool{1: true, 2: true, 7: true}
	// 4 and 9 are alive but unlisted; 5 is neither.
	alive := func(pid int) bool { return pid == 1 || pid == 2 || pid == 4 || pid == 7 || pid == 9 }

	got := hiddenPIDs(listed, 10, alive)
	if want := []int{4, 9}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hiddenPIDs = %v, want %v", got, want)
	}

	// Nothing hidden on a consistent host, which must be the cheap and silent path.
	consistent := map[int]bool{1: true, 2: true}
	if got := hiddenPIDs(consistent, 10, func(p int) bool { return consistent[p] }); len(got) != 0 {
		t.Fatalf("a consistent host reported %v as hidden", got)
	}
}

// TestConfirmHidden is what makes the hidden-process check shippable rather than the noisiest
// thing in the product. Processes start and exit between a /proc read and a signal probe all the
// time, so a single pass sees phantom disagreements constantly. Only a PID hidden in BOTH passes
// and still alive is a rootkit indicator.
func TestConfirmHidden(t *testing.T) {
	alwaysAlive := func(int) bool { return true }

	t.Run("hidden in both passes is reported", func(t *testing.T) {
		got := confirmHidden([]int{4, 9}, []int{9, 4}, alwaysAlive)
		if want := []int{4, 9}; !reflect.DeepEqual(got, want) {
			t.Fatalf("got %v, want %v (sorted)", got, want)
		}
	})

	t.Run("a process that exited mid-scan is not a rootkit", func(t *testing.T) {
		// 4 looked hidden once, then was gone: the ordinary race, not an attack.
		if got := confirmHidden([]int{4}, []int{}, alwaysAlive); len(got) != 0 {
			t.Fatalf("got %v, want nothing", got)
		}
	})

	t.Run("a process that started mid-scan is not a rootkit", func(t *testing.T) {
		// 9 only appeared hidden in the second pass.
		if got := confirmHidden([]int{}, []int{9}, alwaysAlive); len(got) != 0 {
			t.Fatalf("got %v, want nothing", got)
		}
	})

	t.Run("hidden twice but dead by confirmation time is dropped", func(t *testing.T) {
		if got := confirmHidden([]int{4}, []int{4}, func(int) bool { return false }); len(got) != 0 {
			t.Fatalf("got %v, want nothing", got)
		}
	})
}

// TestSuspiciousSUID: the check is an allow-list of suspicious places, not a block-list of safe
// ones. The system suid binaries are legitimate, numerous and differ per distribution, so
// reporting everything outside a known-good list would bury the one that matters.
func TestSuspiciousSUID(t *testing.T) {
	for path, want := range map[string]bool{
		"/tmp/sh":                      true,
		"/var/tmp/.hidden/rootsh":      true,
		"/dev/shm/x":                   true,
		"/home/firdaus/bin/escalate":   true,
		"/run/user/1000/payload":       true,
		"/usr/bin/sudo":                false,
		"/usr/bin/passwd":              false,
		"/bin/ping":                    false,
		"/usr/lib/openssh/ssh-keysign": false,
		// A path that merely CONTAINS a suspect directory name is not in one. Substring matching
		// here would flag every system binary on a host with a /opt/tmp/ directory.
		"/opt/tmphelper/tool": false,
		"/srv/home/app":       false,
	} {
		if got := suspiciousSUID(path); got != want {
			t.Errorf("suspiciousSUID(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestSuspiciousDevFile: /dev holds device nodes, so a regular file there is worth a look, but
// the handful that legitimately exist must not be reported on every single scan or the check
// becomes an hourly false alarm and gets switched off.
func TestSuspiciousDevFile(t *testing.T) {
	for path, want := range map[string]bool{
		"/dev/.hidden-config":        true,
		"/dev/ptyr0":                 true,
		"/dev/srd0":                  true,
		"/dev/null":                  false,
		"/dev/zero":                  false,
		"/dev/log":                   false,
		"/dev/console":               false,
		"/dev/cpu_dma_latency":       false,
		"/dev/shm/sem.mything":       false, // POSIX shared memory: ordinary files live here
		"/dev/mqueue/myqueue":        false,
		"/dev/hugepages/spool":       false,
		"/dev/.lxc/something":        false,
		"/dev/shm/nested/deep/thing": false,
	} {
		if got := suspiciousDevFile(path); got != want {
			t.Errorf("suspiciousDevFile(%q) = %v, want %v", path, got, want)
		}
	}
}
