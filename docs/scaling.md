# Scaling the log pipeline for a large fleet

How the ingest path behaves as you go from a handful of agents to thousands, which knobs to turn,
and where the real ceiling is. The path is:

```
agent (batches 64 lines / 1s, buffers on failure, mTLS)
  -> gateway  (normalize, publish to NATS "logs.normalized")
     -> worker "detect"     : detect -> enrich -> batched INSERT into the events view
     -> worker "archive"    : raw zstd daily files (docs/archive.md)
     -> worker "clickhouse" : analytics mirror (docs/clickhouse.md), if CLICKHOUSE_URL is set
TimescaleDB: 1-day chunks, columnar compression after 7 days (~90% smaller), 30-day retention.
```

## Already optimized

You do not need to do anything to get these; they ship on:

- **Agents gzip their log batches** and the gateway decodes them, so the wire cost per POST is small.
- **The gateway publishes a whole batch in one pipelined round** of async NATS publishes (one wait
  for all acks, not one round trip per line).
- **Events are stored in one multi-row INSERT per batch**, not one round trip per event, and the
  per-row agent-to-tenant lookup is resolved once per batch instead of per row.

## Tuning knobs (worker)

Set these in `deploy/.env` and restart the worker. Defaults are fine for a small fleet; raise them
once you have the traffic to justify it, and measure (see below) rather than guessing.

| Variable | Default | What it does |
|---|---|---|
| `EVENT_BATCH_ROWS` | `200` | Rows aimed for per INSERT. Larger = fewer, bigger inserts under load. The hard cap is 500 (a Postgres bind-parameter limit). `EVENT_BATCH_ROWS=1` turns batching off. |
| `EVENT_BATCH_LINGER` | `200ms` | How long a half-full batch waits before flushing, so a quiet system still stores promptly. This also bounds added latency. |
| `DB_MAX_CONNS` | `30` | Postgres pool size per process. Raise if `PoolStats` shows the pool saturated; keep it under what Postgres `max_connections` allows across all processes. |
| `NATS_URL` | `nats://localhost:4222` | Point at your NATS (or NATS cluster). |

For a busy fleet a reasonable starting point is `EVENT_BATCH_ROWS=500`, `EVENT_BATCH_LINGER=250ms`,
and `DB_MAX_CONNS` sized to your Postgres. Change one thing at a time and watch the numbers.

## Horizontal scale-out

- **Gateway: stateless, scale freely.** It holds no per-agent state, so run several replicas behind a
  TCP (mTLS passthrough) load balancer and point agents at the balancer. They all publish to the same
  NATS. This is the first thing to scale, and it is easy.
- **NATS: cluster it for HA and headroom.** A single NATS node is a single point of failure and, at
  very high rates, a bottleneck. Run a 3-node cluster with file storage; the `LOGS` stream can keep
  replicas across the cluster so an ingest buffer survives a node loss.
- **Postgres / TimescaleDB: vertical first.** Give it CPU, RAM and fast NVMe before anything clever.
  Compression and retention already hold the data size down (docs/storage.md). Tune `DB_MAX_CONNS`.
  For heavy dashboards/reports, add a read replica and point read-only queries at it. ClickHouse
  (docs/clickhouse.md) takes the long-history analytics load off Postgres entirely.

## The real ceiling: the detect stage

The `detect` worker runs the per-event detectors (brute-force counting, single-event rules) **in
memory**. That means you cannot simply run several `detect` workers against the same stream: each
would see only part of the traffic and under-count, so a brute-force that should fire might not.
(The *aggregation* rules are different: they count in SQL, so they already scale with the database.)

In practice one detect worker carries a very large event rate, because the slow part - the database
write - is batched. Scale the gateway, NATS and Postgres first; the detect worker is rarely the first
thing to run out of road.

When it does, there are two ways forward, and it is a design decision rather than a drop-in flag:

1. **Make per-event counting stateless** (count in SQL or Redis), then run N detect workers that
   share the one durable consumer; NATS load-balances the stream across them.
2. **Shard agents across workers** by a stable key (per-subject partitioning), so each worker sees
   every event for its own slice of the fleet and its in-memory counts stay whole.

If you reach this point, raise it and we pick the approach that fits your deployment.

## Measuring

- Worker log lines report stored/sent counts and, on trouble, pool stats.
- Watch the Postgres pool (`PoolStats`) for saturation, and the NATS stream depth: a growing `LOGS`
  stream backlog means consumers are behind the producers (scale the consumer side or the database).
- The Service Health and Agent Monitoring pages show whether agents are keeping up or buffering.
