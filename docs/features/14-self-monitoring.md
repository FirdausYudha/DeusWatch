# 14. Self-monitoring

A security platform that stops working silently is more dangerous than no platform at all: the
dashboard stays green, nobody investigates, and the absence of alerts is read as the absence of
attacks. This module is what DeusWatch does about that — for its agents, for its own backend, and
for the disk underneath it.

It is built on one principle worth stating outright: **the system's own failures travel through
the same pipeline as attacks.** A dead agent becomes a high-severity alert with a MITRE technique,
not a line in a log file nobody tails.

## The three layers

| Layer | Watches | Reported as |
|---|---|---|
| **Agent liveness** | Every enrolled endpoint | `selfhealth` alert, high severity, `T1562.001` |
| **Worker liveness** | The detection worker itself | Red banner on every page in the UI |
| **Disk watermark** | The PostgreSQL data directory | `selfhealth` alert on every trigger |

### Agent liveness

Agents heartbeat to the gateway every 30 seconds. The worker maintains a state per agent:

```
unknown → online → degraded → disconnected → stale
```

- **unknown** — enrolled, never checked in. Something is wrong with the deployment, not the agent.
- **online** — heartbeat fresh, agent reports healthy.
- **degraded** — heartbeat fresh, but the agent reports a problem about *itself*, e.g. its offline
  buffer is piling up because log shipping is failing while the heartbeat still gets through.
- **disconnected** — heartbeats missed past `AGENT_DISCONNECT_AFTER` (default `2m`). **Raises a
  high-severity alert**, because an agent going quiet is a documented adversary technique
  (`T1562.001`, Impair Defenses) and not merely an operations annoyance.
- **stale** — quiet past `AGENT_STALE_AFTER` (default `24h`). Already alerted at disconnect; this
  state exists so a long-decommissioned host does not keep re-alerting.

### Worker liveness

The worker is the **only** consumer of `logs.normalized` and the only writer of events. When it
stops, agents keep shipping and the queue keeps filling, but nothing is detected, nothing is
stored, and nothing is notified — while every screen in the UI carries on rendering over a
database that has quietly stopped growing.

That is not hypothetical. On 2026-09-04 the worker container was absent for over eleven hours on a
live deployment and no screen showed anything wrong. The alarm that should have caught it —
`AGENT_DISCONNECT_AFTER` above — runs *inside the worker*, so the component responsible for
reporting trouble was the one that had vanished.

So the worker is now watched from the manager side:

- The worker writes a heartbeat into `service_heartbeats` every **30s** (migration `000062`),
  carrying its build version.
- The API reports it at `GET /api/system/services`, calling it stale after **100s** — three missed
  beats plus slack, so a GC pause or a brief DB blip cannot fake a crash.
- The web UI polls that every 30s and shows a **red banner above every page**, not a Dashboard
  widget: an operator meets this failure while reading Alerts or Agents, not necessarily while
  looking at the Dashboard.

The heartbeat goes through the database rather than an HTTP probe because both processes already
share that connection — no new network path, no service discovery, and it keeps working when the
api and worker run on different hosts.

**Three states, not two.** The banner distinguishes *stopped reporting* from *never reported*: the
latter means the container was never started at all, which needs different advice from "it
crashed". If the API cannot answer at all, **no banner is shown** — the honest conclusion is "we
don't know", and telling an operator to restart a healthy worker because Postgres hiccupped sends
them to the wrong component.

### Disk watermark

When `STORAGE_BUDGET_GB` is set, the worker watches the log database against it:

- At `STORAGE_ALERT_PERCENT` (default `85`) it notifies through the configured channels.
- At `STORAGE_JANITOR_PERCENT` (default `90`) it **drops the oldest event chunks** and raises a
  high-severity `selfhealth` alert on every trigger — losing the oldest history is preferable to
  PostgreSQL hitting a full disk, but it must never happen quietly.

Both are inert while `STORAGE_BUDGET_GB` is `0`, which is the default.

## How to use

1. **Agents** page — the status pill per endpoint (`online` / `degraded` / `disconnected` /
   `stale` / `never connected`), with the agent's self-reported detail on hover.
2. **Dashboard → Agents widget** — the same states, sorted so the actionable ones come first.
3. **The red banner** appears by itself when the worker stops. It carries the command to bring it
   back, and clears within 30 seconds of the worker's first heartbeat.
4. **Alerts** — `selfhealth` alerts sit alongside attack alerts, searchable and ticketable like
   any other.

### Testing that it actually works

Worth doing once, because an alarm nobody has ever seen fire is an assumption, not a control:

```bash
docker compose -f deploy/docker-compose.yml stop worker
```

The banner should appear within about two minutes. Start it again and it clears within 30
seconds.

## Endpoints & storage

| What | Where |
|---|---|
| Service liveness | `GET /api/system/services` (permission `view_dashboard`) |
| Heartbeat table | `service_heartbeats` (migration `000062`) — one row per component, upserted |
| Agent health | `agents.status`, `agents.health_degraded`, `agents.health_detail`, `agents.last_seen_at` |
| Liveness probes | `/healthz` + `/readyz` on the api (`:8080`), the worker, and `/healthz` on the gateway |
| Banner source | `web/src/components/ServiceHealthBanner.tsx`, mounted above every view in `App.tsx` |

## Variables

| Variable | Default | Effect |
|---|---|---|
| `AGENT_DISCONNECT_AFTER` | `2m` | Silence before an agent is called disconnected (raises a high alert) |
| `AGENT_STALE_AFTER` | `24h` | Silence before an agent is downgraded to stale (no repeat alert) |
| `STORAGE_BUDGET_GB` | `0` (off) | Size budget for the log database |
| `STORAGE_ALERT_PERCENT` | `85` | Percent of budget that triggers a notification |
| `STORAGE_JANITOR_PERCENT` | `90` | Percent of budget at which the oldest chunks are dropped |

The worker's own heartbeat interval (30s) and the API's staleness threshold (100s) are constants,
not environment variables — they are a matched pair, and letting them drift apart in configuration
would produce either false alarms or a blind spot.

## Known gaps

Stated rather than left to be discovered:

- **The gateway and the api are not watched this way.** Only the worker writes a heartbeat. Their
  failure is at least self-announcing — agents log connection errors and the UI stops loading —
  whereas the worker's is silent, which is why it came first.
- **No notification on worker death.** The banner is in-app only. Routing it to Telegram/email
  would mean the notifier surviving the component it reports on, which needs more care than a
  heartbeat read.
