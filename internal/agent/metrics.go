package agent

import "time"

// Host performance metrics (Phase 1): the agent samples its own CPU / memory / disk / network and
// ships gauges, the agentful counterpart to the SNMP board for network gear. Kept as a narrow
// (metric, label, value) set so variable-cardinality series (a disk per mount, a rate per
// interface) need no new field as more are added.

// MetricSample is one gauge at one instant. Label is "" for host-wide gauges, the interface name
// for net_*, the mount point for disk_*.
type MetricSample struct {
	Metric string  `json:"metric"`
	Label  string  `json:"label,omitempty"`
	Value  float64 `json:"value"`
}

// MetricsReport is one sampling tick: a timestamp and the gauges read at it. The agent name is NOT
// here, the manager takes it from the client certificate so a host cannot report as another.
type MetricsReport struct {
	At      time.Time      `json:"at"`
	Samples []MetricSample `json:"samples"`
}

// MetricsSampler produces a point-in-time set of gauges. Stateful: the rate metrics (cpu_pct,
// net_in_bps, net_out_bps) are deltas since the previous Sample, so the first Sample after
// construction returns the instantaneous gauges (memory, disk, load) but no rates yet.
type MetricsSampler interface {
	Sample() []MetricSample
}

// NewMetricsSampler returns the host's sampler, or a no-op one on an OS without a Phase 1 impl
// (currently everything but Linux).
func NewMetricsSampler() MetricsSampler { return newMetricsSampler() }
