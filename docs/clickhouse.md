# ClickHouse analytics sink

DeusWatch can stream every normalized event into a **ClickHouse** table for large-scale,
columnar analytics — top talkers over months, rarest user-agents, arbitrary slice-and-dice —
that return in milliseconds without loading the operational hot path.

ClickHouse is a **secondary, optional store.** TimescaleDB stays the source of truth for
dashboards, alerts, and response; the ClickHouse sink is the cheap, wide, long-retention
analytics layer. The sink is **off unless `CLICKHOUSE_URL` is set.**

## How it works

- A dedicated consumer on `logs.normalized` flattens each event into a wide row (one column per
  useful field — see the schema below) and **batches** inserts over the ClickHouse **HTTP
  interface** (`INSERT … FORMAT JSONEachRow`). No third-party driver is used, so any ClickHouse
  works: self-hosted, `clickhouse-local`, or a managed endpoint.
- On startup the sink **creates the database and table if they don't exist** (idempotent). The
  table is a `MergeTree` partitioned by month and ordered by `(timestamp, source_ip)`.
- A failed insert **requeues the batch** for the next flush rather than dropping it.
- The two CTI confidence columns (`abuse_confidence`, `otx_pulse_count`) are `Nullable` so
  "never looked up" stays distinct from a real score of 0.

## Enable

Set these in the worker's environment:

```dotenv
# deploy/.env
CLICKHOUSE_URL=http://clickhouse:8123   # required; empty = disabled
CLICKHOUSE_DATABASE=deuswatch           # default deuswatch
CLICKHOUSE_TABLE=events                 # default events
CLICKHOUSE_USER=                        # optional
CLICKHOUSE_PASSWORD=                     # optional
CLICKHOUSE_BATCH=1000                    # rows per insert (default 1000)
CLICKHOUSE_FLUSH=5s                      # max time a row waits in the buffer (default 5s)
CLICKHOUSE_RETENTION_DAYS=0              # >0 adds a TTL so rows age out; 0 = keep forever
```

A minimal ClickHouse for testing:

```bash
docker run -d --name clickhouse -p 8123:8123 -p 9000:9000 clickhouse/clickhouse-server
```

The worker log shows `worker: clickhouse analytics sink active (http://clickhouse:8123 db=deuswatch table=events)`.

## Query it

```sql
-- top source IPs by event count this month
SELECT source_ip, count() AS n
FROM deuswatch.events
WHERE timestamp >= toStartOfMonth(now())
GROUP BY source_ip ORDER BY n DESC LIMIT 20;

-- brute-force attempts against WordPress logins, by day
SELECT toDate(timestamp) AS d, count() AS n
FROM deuswatch.events
WHERE http_uri = '/wp-login.php' AND event_outcome = 'failure'
GROUP BY d ORDER BY d;
```

## Schema

Columns mirror the DeusWatch Core Schema flattened one level: `timestamp`, `event_category`,
`event_action`, `event_outcome`, `severity`, `dataset`, `source_ip`/`source_port`/
`source_country`/`source_city`, `dest_ip`/`dest_port`, `host_name`, `agent_id`, `user_name`,
`http_method`/`http_uri`/`http_status`/`http_host`, `file_path`/`file_hash`, `process_name`/
`process_pid`, `rule_id`/`rule_name`, `mitre_technique_id`/`mitre_technique_name`/`mitre_tactic`,
`threat_indicator_ip`/`threat_confidence`/`threat_feed`, `label`, `abuse_confidence`,
`otx_pulse_count`, `llm_verdict`, `file_hash_verdict`, `remediation_action`,
`remediation_status`.

The row layout and the `CREATE TABLE` DDL live together in
[`internal/clickhouse`](../internal/clickhouse/) and must stay in lockstep.

## Notes

- This is separate from the [raw daily archive](archive.md): the archive keeps the raw text; the
  ClickHouse sink keeps **structured, queryable** columns. Use both, or either, independently.
- Point ClickHouse at cheap/large storage for long retention; set `CLICKHOUSE_RETENTION_DAYS` to
  age rows out automatically.
- The sink is fire-and-forget from the pipeline's perspective — if ClickHouse is down, events
  still flow to TimescaleDB and the batch is retried; ClickHouse being unavailable never blocks
  ingestion.
