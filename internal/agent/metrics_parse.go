package agent

// Pure parsers for the Linux /proc files the sampler reads. Untagged (not build-constrained) so the
// string parsing is unit-tested on any OS; the sampler that calls them, and the statfs syscall, are
// in metrics_linux.go.

import (
	"strconv"
	"strings"
)

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// parseCPU reads the aggregate "cpu " line of /proc/stat into busy and total jiffies. idle counts
// idle+iowait; busy is everything else, so busy/total is the fraction of time the CPU had work.
func parseCPU(stat string) (busy, total uint64, ok bool) {
	for _, line := range strings.Split(stat, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)[1:] // user nice system idle iowait irq softirq steal ...
		var idle uint64
		for i, s := range f {
			n, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				continue
			}
			total += n
			if i == 3 || i == 4 { // idle, iowait
				idle += n
			}
		}
		return total - idle, total, total > 0
	}
	return 0, 0, false
}

// parseMem turns /proc/meminfo (values in kB) into the memory gauges.
func parseMem(meminfo string) []MetricSample {
	var totalKB, availKB int64
	haveAvail := false
	for _, line := range strings.Split(meminfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			totalKB = v
		case "MemAvailable:":
			availKB, haveAvail = v, true
		}
	}
	if totalKB <= 0 || !haveAvail {
		return nil
	}
	usedKB := totalKB - availKB
	if usedKB < 0 {
		usedKB = 0
	}
	return []MetricSample{
		{Metric: "mem_pct", Value: clampPct(float64(usedKB) / float64(totalKB) * 100)},
		{Metric: "mem_used_mb", Value: float64(usedKB) / 1024},
		{Metric: "mem_total_mb", Value: float64(totalKB) / 1024},
	}
}

// virtualIface drops loopback and the churn of container/bridge/virtual interfaces, which would
// otherwise bury a host's real NIC under dozens of veth* rows on a Docker host.
func virtualIface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range []string{"veth", "docker", "br-", "virbr", "flannel", "cni", "tun", "tap", "kube"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// parseNetDev reads /proc/net/dev into per-interface {rxBytes, txBytes}, skipping virtual ones.
func parseNetDev(dev string) map[string][2]uint64 {
	out := map[string][2]uint64{}
	for _, line := range strings.Split(dev, "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue // header lines have no colon
		}
		name = strings.TrimSpace(name)
		if name == "" || virtualIface(name) {
			continue
		}
		f := strings.Fields(rest) // rxBytes rxPkts ... (16 columns); txBytes is column 8
		if len(f) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(f[0], 10, 64)
		tx, err2 := strconv.ParseUint(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[name] = [2]uint64{rx, tx}
	}
	return out
}

// realFSTypes is the set of mounted filesystems worth a usage gauge: actual storage, not the dozens
// of pseudo-filesystems (proc, sysfs, cgroup, tmpfs, overlay, squashfs) the kernel also mounts.
var realFSTypes = map[string]bool{
	"ext4": true, "ext3": true, "ext2": true, "xfs": true, "btrfs": true,
	"zfs": true, "vfat": true, "f2fs": true, "jfs": true, "reiserfs": true,
}

// parseMounts returns the mount points of real filesystems from /proc/mounts, de-duplicated.
func parseMounts(mounts string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(mounts, "\n") {
		f := strings.Fields(line) // device mountpoint fstype options ...
		if len(f) < 3 || !realFSTypes[f[2]] {
			continue
		}
		mp := f[1]
		if seen[mp] {
			continue
		}
		seen[mp] = true
		out = append(out, mp)
	}
	return out
}
