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

// TestLatchNewSuppressesRepeats is the fix for the flood: a finding present in consecutive scans
// is reported once, not every scan. Without it a host with standing findings produces hundreds of
// alerts a minute forever.
func TestLatchNewSuppressesRepeats(t *testing.T) {
	a := RootcheckFinding{Check: CheckSUIDInTemp, Path: "/tmp/rootsh"}
	b := RootcheckFinding{Check: CheckFileInDev, Path: "/dev/.hidden"}

	// First scan: both are new, both reported.
	fresh, seen := latchNew(nil, []RootcheckFinding{a, b})
	if len(fresh) != 2 {
		t.Fatalf("first scan emitted %d, want 2", len(fresh))
	}

	// Second scan, same findings still present: nothing new, so nothing emitted.
	fresh, seen = latchNew(seen, []RootcheckFinding{a, b})
	if len(fresh) != 0 {
		t.Fatalf("a standing finding was re-emitted: %d", len(fresh))
	}

	// A genuinely new finding appears alongside the standing ones: only it is emitted.
	c := RootcheckFinding{Check: CheckSUIDInTemp, Path: "/tmp/newsh"}
	fresh, seen = latchNew(seen, []RootcheckFinding{a, b, c})
	if len(fresh) != 1 || fresh[0].Path != "/tmp/newsh" {
		t.Fatalf("expected only the new finding, got %+v", fresh)
	}

	// A finding that CLEARS drops from the latch, so if it returns later it is reported again,
	// a suid binary dropped a second time is news.
	fresh, seen = latchNew(seen, []RootcheckFinding{a}) // b and c gone
	if len(fresh) != 0 {
		t.Fatalf("clearing findings should emit nothing, got %d", len(fresh))
	}
	fresh, _ = latchNew(seen, []RootcheckFinding{a, c}) // c returns
	if len(fresh) != 1 || fresh[0].Path != "/tmp/newsh" {
		t.Fatalf("a finding that cleared and returned should be re-reported, got %+v", fresh)
	}
}

// TestFindingKeyDistinguishes: two different findings must not collide into one latch entry, or a
// real second finding would be silently suppressed.
func TestFindingKeyDistinguishes(t *testing.T) {
	keys := map[string]bool{}
	for _, f := range []RootcheckFinding{
		{Check: CheckSUIDInTemp, Path: "/tmp/a"},
		{Check: CheckSUIDInTemp, Path: "/tmp/b"},
		{Check: CheckFileInDev, Path: "/tmp/a"}, // same path, different check
		{Check: CheckHiddenProcess, PID: 1337},
		{Check: CheckHiddenProcess, PID: 1338},
	} {
		keys[findingKey(f)] = true
	}
	if len(keys) != 5 {
		t.Fatalf("expected 5 distinct keys, got %d (a collision hides a real finding)", len(keys))
	}
}
