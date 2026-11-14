//go:build !linux

package agent

// No host-metrics sampler off Linux yet (Phase 1 is Linux-only). A no-op so the agent builds and
// runs everywhere; Phase 2 adds Windows and macOS impls behind the same NewMetricsSampler.
type nopSampler struct{}

func (nopSampler) Sample() []MetricSample { return nil }

func newMetricsSampler() MetricsSampler { return nopSampler{} }
