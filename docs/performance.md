# Host performance monitoring

The **Performance** view (a tab under **Agent Health**) charts CPU, memory, disk and network over
time for hosts that run the DeusWatch agent. It is the agentful counterpart to the SNMP **Network**
board: where Network polls switches and routers that cannot run an agent, Performance uses the agent
you already have. For a one-row-per-agent summary across the whole fleet, see the **Agent
Monitoring** dashboard (`docs/agent-monitoring.md`).

Nothing new listens on the host and no SNMP is enabled. The agent samples its own `/proc` and
`statfs` and ships the numbers over the same mTLS channel it already uses for everything else, so a
workstation is monitored without opening another service on it.

---

## What it collects (Linux)

Every 30 seconds the agent reports:

| Metric | Notes |
|---|---|
| CPU busy % | fraction of time the CPU had work, across all cores |
| Load average (1 min) | from `/proc/loadavg` |
| Uptime | seconds since boot, from `/proc/uptime` (shown on the Agent Monitoring dashboard) |
| Memory used % | total minus `MemAvailable`, so cache that can be reclaimed is not counted as used |
| Disk usage % per filesystem | real filesystems only; pseudo-mounts (tmpfs, overlay, squashfs, ...) are skipped |
| Network throughput per interface | bytes/sec in and out; loopback and virtual/container interfaces (veth, docker, br-, ...) are skipped so a Docker host is not buried under dozens of lines |

CPU % and network throughput are rates, computed from the difference between two samples, so they
appear from the **second** sample on (about 60 seconds after start), not the first.

> **Linux only for now.** On Windows and macOS the agent runs normally but reports no performance
> metrics yet. The sampler is a no-op there; support is planned.

---

## Enable, disable and tune

On by default. Environment variables on the agent:

| Variable | Default | Effect |
|---|---|---|
| `METRICS` | on | set `METRICS=0` to turn host metrics off entirely |
| `METRICS_INTERVAL` | `30s` | sample interval (Go duration, minimum `1s`); lower it (e.g. `10s`) for finer graphs at the cost of more rows |

---

## Using it

Pick a host from the dropdown, then a time range: `1m`, `10m`, `30m`, `1h`, `6h`, `24h`, `7d`, or
**Custom** (pick a from/to). A host appears in the picker after its first report.

Resolution is bounded by the sample interval: at the default 30s a one-minute view is only about two
points. The short ranges are for glancing at near-real-time, not for a smooth line; widen the range
for a readable trend, or lower `METRICS_INTERVAL` for denser short-range graphs.

---

## Retention

Samples are kept **30 days**, then dropped automatically. They are stored raw (no rollup); charts
downsample on read with `time_bucket`, so even a seven-day view draws as a few hundred points rather
than every raw sample.

If you add many agents or sample much faster, the raw table becomes the thing to watch. Add a
continuous aggregate (a 5-minute or 1-hour rollup) and a shorter raw retention then; the note in
migration `000089_host_metrics.up.sql` says where.

---

## Requirements

- A host running an agent build that includes host metrics (this release or newer). An older agent
  simply reports nothing; update it via self-update or by reinstalling.
- Timescale is already in the stack (the same hypertable machinery the SNMP and event history use).

Empty board? If no host appears, no agent has reported yet: check the agent is online and on a build
with metrics, and that `METRICS=0` is not set. If a host is listed but a window is empty, widen the
range or confirm the agent has been up longer than one sample interval.
