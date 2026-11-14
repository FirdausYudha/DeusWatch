package store

// Host performance metrics (Phase 1): agent-reported CPU / memory / disk / network gauges, stored
// as narrow (time, agent, metric, label, value) rows in the host_metrics hypertable. Writes come
// from the gateway (agent -> POST /v1/metrics); reads serve the Performance page, downsampled with
// time_bucket so a month of 30-second samples still draws as a few hundred points.

import (
	"context"
	"fmt"
	"time"
)

// HostMetricSample is one gauge to store. Label is "" for host-wide gauges, an interface for net_*,
// a mount point for disk_*.
type HostMetricSample struct {
	Metric string
	Label  string
	Value  float64
}

// MetricPoint is one downsampled value at a bucket boundary.
type MetricPoint struct {
	T time.Time `json:"t"`
	V float64   `json:"v"`
}

// MetricSeries is one (metric, label) line over the window.
type MetricSeries struct {
	Metric string        `json:"metric"`
	Label  string        `json:"label"`
	Points []MetricPoint `json:"points"`
}

// InsertHostMetrics appends one sampling tick for an agent. The tenant is stamped from the agents
// table (falling back to the default tenant), so a metric is isolated the same way the host's events
// are, without trusting the agent to name its own tenant.
func (s *Store) InsertHostMetrics(ctx context.Context, agentName string, at time.Time, samples []HostMetricSample) error {
	if agentName == "" {
		return fmt.Errorf("store: host metrics need an agent name")
	}
	metrics := make([]string, 0, len(samples))
	labels := make([]string, 0, len(samples))
	values := make([]float64, 0, len(samples))
	for _, m := range samples {
		if m.Metric == "" {
			continue
		}
		metrics = append(metrics, m.Metric)
		labels = append(labels, m.Label)
		values = append(values, m.Value)
	}
	if len(metrics) == 0 {
		return nil
	}
	if _, err := s.q(ctx).Exec(ctx, `
		INSERT INTO host_metrics (time, agent_name, tenant_id, metric, label, value)
		SELECT $1, $2,
		       COALESCE((SELECT tenant_id FROM agents WHERE name = $2),
		                '00000000-0000-0000-0000-000000000001'::uuid),
		       u.metric, u.label, u.value
		  FROM unnest($3::text[], $4::text[], $5::double precision[]) AS u(metric, label, value)`,
		at, agentName, metrics, labels, values); err != nil {
		return fmt.Errorf("store: insert host metrics: %w", err)
	}
	return nil
}

// HostMetricSeries returns every (metric, label) line for one agent in [since, until], averaged into
// buckets of `bucket` width. A zero `until` means now. The bucket is floored at a second, so a
// one-minute window keeps whatever resolution the agent actually sampled at.
func (s *Store) HostMetricSeries(ctx context.Context, agentName string, since, until time.Time, bucket time.Duration) ([]MetricSeries, error) {
	if agentName == "" {
		return nil, fmt.Errorf("store: metric series needs an agent name")
	}
	if bucket < time.Second {
		bucket = time.Second
	}
	if until.IsZero() {
		until = time.Now()
	}
	rows, err := s.q(ctx).Query(ctx, `
		SELECT metric, label, time_bucket(make_interval(secs => $4), time) AS tb, avg(value)
		  FROM host_metrics
		 WHERE agent_name = $1 AND time >= $2 AND time <= $3
		 GROUP BY metric, label, tb
		 ORDER BY metric, label, tb`, agentName, since, until, bucket.Seconds())
	if err != nil {
		return nil, fmt.Errorf("store: host metric series: %w", err)
	}
	defer rows.Close()

	out := []MetricSeries{}
	for rows.Next() {
		var metric, label string
		var t time.Time
		var v float64
		if err := rows.Scan(&metric, &label, &t, &v); err != nil {
			return nil, err
		}
		// Rows are ordered by (metric, label), so a change in either starts a new series.
		if n := len(out); n == 0 || out[n-1].Metric != metric || out[n-1].Label != label {
			out = append(out, MetricSeries{Metric: metric, Label: label})
		}
		last := &out[len(out)-1]
		last.Points = append(last.Points, MetricPoint{T: t, V: v})
	}
	return out, rows.Err()
}

// HostsWithMetrics lists the agents that have reported metrics recently, for the page's host picker.
func (s *Store) HostsWithMetrics(ctx context.Context) ([]string, error) {
	rows, err := s.q(ctx).Query(ctx, `
		SELECT DISTINCT agent_name FROM host_metrics
		 WHERE time >= now() - interval '7 days' ORDER BY agent_name`)
	if err != nil {
		return nil, fmt.Errorf("store: hosts with metrics: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
