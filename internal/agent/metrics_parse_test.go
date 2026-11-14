package agent

import "testing"

func TestParseCPU(t *testing.T) {
	// user=100 nice=0 system=50 idle=800 iowait=50 (rest 0): total 1000, idle 850, busy 150.
	busy, total, ok := parseCPU("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n")
	if !ok || total != 1000 || busy != 150 {
		t.Fatalf("parseCPU = busy %d total %d ok %v; want 150/1000/true", busy, total, ok)
	}
}

func TestParseMem(t *testing.T) {
	got := map[string]float64{}
	for _, m := range parseMem("MemTotal:       2000 kB\nMemFree:         100 kB\nMemAvailable:    500 kB\n") {
		got[m.Metric] = m.Value
	}
	// used = 2000-500 = 1500 kB -> 75%.
	if got["mem_pct"] != 75 {
		t.Fatalf("mem_pct = %v; want 75", got["mem_pct"])
	}
	if _, ok := got["mem_used_mb"]; !ok {
		t.Fatal("mem_used_mb missing")
	}
}

func TestParseNetDevSkipsVirtual(t *testing.T) {
	dev := "Inter-|   Receive                    |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets ...\n" +
		"    lo:  1000       10    0    0    0     0          0         0   1000      10\n" +
		"  eth0: 500000      100    0    0    0     0          0         0 250000      80\n" +
		"veth9a:  7777        1    0    0    0     0          0         0   888        1\n"
	m := parseNetDev(dev)
	if _, ok := m["lo"]; ok {
		t.Error("loopback should be skipped")
	}
	if _, ok := m["veth9a"]; ok {
		t.Error("veth* should be skipped")
	}
	if got := m["eth0"]; got[0] != 500000 || got[1] != 250000 {
		t.Fatalf("eth0 = %v; want [500000 250000]", got)
	}
}

func TestParseMounts(t *testing.T) {
	mounts := "proc /proc proc rw 0 0\n" +
		"/dev/sda1 / ext4 rw,relatime 0 0\n" +
		"tmpfs /run tmpfs rw 0 0\n" +
		"/dev/sda1 / ext4 rw 0 0\n" + // duplicate mountpoint
		"/dev/sdb1 /data xfs rw 0 0\n"
	got := parseMounts(mounts)
	if len(got) != 2 || got[0] != "/" || got[1] != "/data" {
		t.Fatalf("parseMounts = %v; want [/ /data]", got)
	}
}
