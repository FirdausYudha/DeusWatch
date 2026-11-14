//go:build linux

package agent

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const mbDiv = 1024 * 1024

// linuxSampler reads the host's own counters out of /proc and statfs. It holds the previous CPU and
// network counters so the rate metrics are a delta over wall-clock time, the way every host monitor
// computes them: /proc exposes cumulative ticks and byte counters, not rates.
type linuxSampler struct {
	prevCPUBusy, prevCPUTotal uint64
	haveCPU                   bool
	prevNet                   map[string][2]uint64 // iface -> {rxBytes, txBytes}
	prevNetAt                 time.Time
}

func newMetricsSampler() MetricsSampler { return &linuxSampler{} }

func (s *linuxSampler) Sample() []MetricSample {
	var out []MetricSample
	now := time.Now()

	// CPU: busy fraction since the previous sample. Skipped on the first call (no baseline yet).
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		if busy, total, ok := parseCPU(string(b)); ok {
			if s.haveCPU && total > s.prevCPUTotal {
				dt := float64(total - s.prevCPUTotal)
				if dt > 0 {
					pct := float64(busy-s.prevCPUBusy) / dt * 100
					out = append(out, MetricSample{Metric: "cpu_pct", Value: clampPct(pct)})
				}
			}
			s.prevCPUBusy, s.prevCPUTotal, s.haveCPU = busy, total, true
		}
	}

	// Load average (1 min). A gauge, no baseline needed.
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				out = append(out, MetricSample{Metric: "load1", Value: v})
			}
		}
	}

	// Uptime in seconds (since boot). First field of /proc/uptime.
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				out = append(out, MetricSample{Metric: "uptime_sec", Value: v})
			}
		}
	}

	// Memory. "Used" is total-available (MemAvailable already accounts for reclaimable cache), which
	// is the number a person means by "how full is RAM", not total-free.
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		out = append(out, parseMem(string(b))...)
	}

	// Network: bytes/sec per real interface since the previous sample.
	if b, err := os.ReadFile("/proc/net/dev"); err == nil {
		cur := parseNetDev(string(b))
		if s.prevNet != nil {
			if elapsed := now.Sub(s.prevNetAt).Seconds(); elapsed > 0 {
				for iface, cnt := range cur {
					prev, ok := s.prevNet[iface]
					if !ok || cnt[0] < prev[0] || cnt[1] < prev[1] {
						continue // new interface, or a counter reset/wrap: no honest rate this tick
					}
					out = append(out,
						MetricSample{Metric: "net_in_bps", Label: iface, Value: float64(cnt[0]-prev[0]) / elapsed},
						MetricSample{Metric: "net_out_bps", Label: iface, Value: float64(cnt[1]-prev[1]) / elapsed})
				}
			}
		}
		s.prevNet, s.prevNetAt = cur, now
	}

	// Disk usage per real mounted filesystem.
	for _, m := range parseMounts(readFileOr("/proc/mounts")) {
		var st syscall.Statfs_t
		if syscall.Statfs(m, &st) != nil || st.Blocks == 0 {
			continue
		}
		bs := uint64(st.Bsize)
		total := st.Blocks * bs
		used := (st.Blocks - st.Bfree) * bs
		out = append(out,
			MetricSample{Metric: "disk_used_pct", Label: m, Value: clampPct(float64(used) / float64(total) * 100)},
			MetricSample{Metric: "disk_used_mb", Label: m, Value: float64(used) / mbDiv},
			MetricSample{Metric: "disk_total_mb", Label: m, Value: float64(total) / mbDiv})
	}

	return out
}

func readFileOr(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
