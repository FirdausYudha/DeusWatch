# Throughput and the event batch

How many events per second DeusWatch sustains, what limits it, and the one knob worth turning.

## Measure before you tune

There is no published events-per-second figure for DeusWatch, and a number invented here would be
worse than none. What follows describes where the limits are in the code so you can find yours.

The pipeline is: agent or syslog -> `logs.raw` -> normalize -> `logs.normalized` -> the detect
consumer -> Postgres. The detect consumer is the narrow part, and it is where the batch lives.

## Why a batch, and why it is not COPY

Until v2.61.0 the detect consumer sent one `INSERT` per event, 55 bind parameters, and waited for
it. The NATS callback is **serial**, one message at a time, so that wait was not merely slow per
event, it was the ceiling for the whole pipeline: nothing else could be decoded, enriched or
matched while the worker sat on a round trip.

Now ordinary events go into a buffer and are stored with one multi-row `INSERT` per batch. The
consumer keeps pulling while the batch fills.

It is an `INSERT`, not a `pgx.CopyFrom`, and that is deliberate:

* `events` is a VIEW with `security_barrier`, which is what makes tenant isolation hold. `COPY`
  does not accept a view, so a copy would have to target the hypertable underneath and step
  around the tenant filter.
* Tenant stamping runs a per-row subquery (explicit override, then the producing agent's tenant,
  then the Default tenant). `COPY` cannot run it.

A multi-row `INSERT` keeps the view, the barrier, the `inet` casts and the tenant precedence
exactly as a single insert had them. The win is in the round trips, and that was the cost.

## Durability is unchanged

This is the part to be suspicious of, so it is worth stating plainly: **a batched event is
acknowledged to JetStream only after its `INSERT` has committed.**

Acknowledging on enqueue would be faster and would quietly lose every buffered event on a crash,
with no redelivery, because JetStream would already consider them handled. Instead the bus hands
the handler a `done` callback, the handler returns immediately, and the batch loop calls `done`
once the statement commits. A worker killed with a full buffer loses nothing: those messages were
never acked and come back.

A failed insert Naks the whole batch, so all of it is redelivered rather than part of it being
dropped.

## Alerts are not batched

Only ordinary events are. An alert, whether a rule fired it or it arrived pre-labeled from
Suricata, is stored on its own and committed before response and notification run, because those
read the alert back. Batching them would let a block be executed against a row that is not there
yet. Alerts are a rounding error in the volume anyway, so there is nothing to win.

## The knobs

| Variable | Default | What it does |
|---|---|---|
| `EVENT_BATCH_ROWS` | `200` | Rows the batch aims for, and twice this is the buffer depth |
| `EVENT_BATCH_LINGER` | `200ms` | How long a part-full batch waits before going anyway |

`EVENT_BATCH_ROWS=1` turns batching off and restores the per-event insert. Use it to confirm a
problem is or is not the batch, not as a setting.

Raising rows past a few hundred buys little: Postgres allows at most 65535 bind parameters per
statement, so the hard ceiling is 500 rows at 55 columns, and the statement is chunked at that
bound regardless of what you set.

Lowering `EVENT_BATCH_LINGER` makes an idle system store events sooner and makes a busy one send
smaller statements. It does not affect alerts, which never wait.

## What is still single-threaded

Batching removed the wait, not the serialisation. Decode, enrich and rule matching for ordinary
events still happen one event at a time in the consumer callback. If a profile shows the time
going to GeoIP lookups or Sigma matching rather than to Postgres, the batch is not your problem
and a wider change is needed.

There is also still exactly one worker. There is no leader election, so a second worker instance
would duplicate the scoring, aggregation and sweep loops rather than share them. Scale the agents
and the log sources, not the worker, until that changes.
