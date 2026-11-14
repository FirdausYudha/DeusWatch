# Agent Monitoring dashboard

The **Agent Monitoring** dashboard is one row per endpoint, pulling together every per-agent
monitoring signal the product already collects. The default **Dashboard** answers "what is happening
on the network"; this answers "how is each endpoint doing".

It invents no new data: it joins, by agent, what the other views already gather.

## What each column shows

| Column | Source | Meaning |
|---|---|---|
| Status | agent heartbeat | online / stale / offline / never seen / revoked |
| CPU, Memory, Disk | Performance (host metrics) | the agent's most recent reading; **Disk** is the fullest mounted filesystem. A dash means no sample in the last 15 minutes |
| Uptime | Performance (host metrics) | time since the host booted (Linux); a dash means no recent sample |
| FIM 24h | File Integrity | file-integrity alerts in the last 24 hours (a change that matched a detection rule, not every change) |
| VA c/h | Vulnerability Assessment | OS-package vulnerabilities: critical / high |
| SCA c/h | Software Composition Analysis | dependency vulnerabilities: critical / high |
| CIS | Benchmarks | hardening score (average across the agent's policies) |

The summary cards at the top count agents, how many are online, how many are offline or stale, how
many carry a critical vulnerability (VA or SCA), total FIM alerts in the last 24h, and the fleet's
average CIS score.

## Reading it

- A dash in CPU/Memory/Disk is normal for a host on an OS without the metrics sampler (currently
  anything but Linux), or one that has not reported in the last 15 minutes. Status still shows
  whether it is alive.
- A dash in CIS means no benchmark has run for that agent yet (no `sca` source or no policy); see
  `docs/benchmarks.md`.
- The board refreshes itself every 30 seconds.

## Where the detail lives

This dashboard is deliberately shallow - a status board, not a drill-down. For the detail behind a
number, open the dedicated view:

- CPU/memory/disk/network over time: **Agent Health -> Performance** (`docs/performance.md`)
- the actual CVEs: **Agent Health -> Vulnerability Assessment** and **-> SCA**
- which hardening controls failed: **Agent Health -> CIS Benchmark** (`docs/benchmarks.md`)
