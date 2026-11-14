-- Migration 000089 - host performance metrics (Phase 1: agent-reported CPU / memory / disk / net).
--
-- The Cacti-style half of monitoring, but for hosts that already run the DeusWatch agent rather than
-- over SNMP: the agent samples itself and ships gauges. SNMP stays for agentless gear (snmp_*).
--
-- One narrow row per (time, agent, metric, label) so variable-cardinality series (a disk per mount,
-- a rate per interface) need no schema change as Phase 2 adds them. Same day-chunk + retention
-- treatment as snmp_readings. Charts downsample at read time with time_bucket, so raw density here
-- is bounded only by retention, not by what a browser has to draw.
--
-- ponytail: raw samples + a 30-day retention policy, no continuous aggregate. At a handful of agents
-- and a 30s interval this is ~0.9M rows per agent per month, which Timescale handles fine. Add a
-- continuous aggregate (5-min/1-hour rollup) + a shorter raw retention when agent count or sample
-- rate makes the raw table the bottleneck.

CREATE TABLE IF NOT EXISTS host_metrics (
    time       timestamptz NOT NULL,
    agent_name text        NOT NULL,
    tenant_id  uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    -- cpu_pct | mem_pct | mem_used_mb | mem_total_mb | load1 | net_in_bps | net_out_bps |
    -- disk_used_pct | disk_used_mb | disk_total_mb  (the set the Linux sampler emits in Phase 1)
    metric     text        NOT NULL,
    -- "" for host-wide gauges; the interface for net_*, the mount point for disk_*.
    label      text        NOT NULL DEFAULT '',
    value      double precision NOT NULL
);

SELECT create_hypertable(
    'host_metrics', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS host_metrics_agent_metric_time_idx
    ON host_metrics (agent_name, metric, time DESC);

SELECT add_retention_policy('host_metrics', INTERVAL '30 days', if_not_exists => TRUE);

-- Tenant isolation, same fail-closed policy every other tenant-scoped table carries (000050).
ALTER TABLE host_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE host_metrics FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON host_metrics;
CREATE POLICY tenant_isolation ON host_metrics
    USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))
    WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()));
