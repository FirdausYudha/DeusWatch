# 14. Self-monitoring

A security platform that stops working silently is more dangerous than no platform at all: the
dashboard stays green, nobody investigates, and the absence of alerts is read as the absence of
attacks. This module is what DeusWatch does about that, for its agents, for its own backend, and
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

- **unknown**: enrolled, never checked in. Something is wrong with the deployment, not the agent.
- **online**: heartbeat fresh, agent reports healthy.
- **degraded**: heartbeat fresh, but the agent reports a problem about *itself*, e.g. its offline
  buffer is piling up because log shipping is failing while the heartbeat still gets through.
- **disconnected**: heartbeats missed past `AGENT_DISCONNECT_AFTER` (default `2m`). **Raises a
  high-severity alert**, because an agent going quiet is a documented adversary technique
  (`T1562.001`, Impair Defenses) and not merely an operations annoyance.
- **stale**: quiet past `AGENT_STALE_AFTER` (default `24h`). Already alerted at disconnect; this
  state exists so a long-decommissioned host does not keep re-alerting.

### Worker liveness

The worker is the **only** consumer of `logs.normalized` and the only writer of events. When it
stops, agents keep shipping and the queue keeps filling, but nothing is detected, nothing is
stored, and nothing is notified, while every screen in the UI carries on rendering over a
database that has quietly stopped growing.

That is not hypothetical. On 2026-09-04 the worker container was absent for over eleven hours on a
live deployment and no screen showed anything wrong. The alarm that should have caught it,
`AGENT_DISCONNECT_AFTER` above, runs *inside the worker*, so the component responsible for
reporting trouble was the one that had vanished.

So the worker is now watched from the manager side:

- The worker writes a heartbeat into `service_heartbeats` every **30s** (migration `000062`),
  carrying its build version.
- The API reports it at `GET /api/system/services`, calling it stale after **100s**: three missed
  beats plus slack, so a GC pause or a brief DB blip cannot fake a crash.
- The web UI polls that every 30s and shows a **red banner above every page**, not a Dashboard
  widget: an operator meets this failure while reading Alerts or Agents, not necessarily while
  looking at the Dashboard.

The heartbeat goes through the database rather than an HTTP probe because both processes already
share that connection: no new network path, no service discovery, and it keeps working when the
api and worker run on different hosts.

**Three states, not two.** The banner distinguishes *stopped reporting* from *never reported*: the
latter means the container was never started at all, which needs different advice from "it
crashed". If the API cannot answer at all, **no banner is shown**, the honest conclusion is "we
don't know", and telling an operator to restart a healthy worker because Postgres hiccupped sends
them to the wrong component.

### Worker recovery: never "restart it by hand"

Detecting that the worker died is only half the job. An operator should never have to run
`docker compose up -d worker` themselves, so each way it can stop has something that brings it back.

These are not hypothetical either. All three were hit on a live deployment, and they all *looked*
identical from the UI ("worker stopped reporting, restart it"), which is exactly why they are listed
separately: the same symptom had three different causes and three different fixes.

| How it stops | What brings it back | Automatic? |
|---|---|---|
| A background job panics | `safeGo` recovers the panic, logs the stack, restarts that loop after 3s | Yes |
| The process exits (crash, fatal error) | `restart: unless-stopped` | Yes |
| The kernel OOM-kills it | `restart: unless-stopped` | Yes |
| The DB path wedges, heartbeats stop | The watchdog calls `os.Exit(1)`, docker restarts it | Yes |
| The process is alive but wedged solid | Container healthcheck marks it unhealthy, optional `autoheal` restarts it | Yes, if enabled |
| The container was never created | The host watchdog recreates it (`deploy/systemd/`) | Yes, if installed |

Two details in that table are worth the words, because both were real bugs:

**The watchdog must not share a goroutine with the thing it watches.** It originally checked
staleness immediately after writing the heartbeat, in the same loop. When the write itself hung on a
wedged connection, the check below it never ran and the process sat alive-but-dead forever. The
watchdog is now a dedicated goroutine that does nothing but read a clock, and the clock is a
package-level atomic rather than a local variable, so a supervised restart of the heartbeat loop
cannot silently reset the staleness window.

**`restart: unless-stopped` only applies to a container that exists.** If a deploy fails after the
old container is removed but before the new one starts, there is nothing to restart and no amount of
in-process cleverness helps. The practical defence is to keep the worker image build from depending
on anything that can fail, which is why it builds from the plain static target with no external
image pull.

#### The healthcheck

`/healthz` on the worker fails once no heartbeat has been written for `WORKER_STALL_LIMIT`, the same
condition that means detection has stopped. It used to return `200` unconditionally, which made it
useless as a healthcheck: a wedged worker reported itself healthy.

The worker image is distroless, so there is no shell, `curl` or `wget` inside it to probe with. The
binary therefore probes itself: `/app -healthcheck` requests its own `/healthz` and exits `0` or `1`,
handled before any database or NATS setup so the probe stays cheap and side-effect free. That is what
`docker compose ps` reads when it shows `Up (healthy)`.

#### The host watchdog (the one that covers everything)

Every mechanism above runs *inside* the stack, and each has a blind spot: `restart: unless-stopped`
needs a container that exists, the in-process watchdog needs a process healthy enough to run a
goroutine, and an autoheal container can restart an unhealthy container but cannot recreate a
missing one. The blind spot they share is the failure that actually caused the longest outage here,
a deploy that removed the worker and never recreated it.

`deploy/systemd/` contains a small timer that closes all of them from the host: every minute it
checks whether the worker is running and healthy, and runs `docker compose up -d worker` if it is
missing, exited, restarting or unhealthy. No extra container, nothing holding the Docker socket.
Install instructions and a recovery test are in [`deploy/systemd/README.md`](../../deploy/systemd/README.md).

This is the recommended answer if you ever had to restart the worker by hand. Note what it does
*not* do: it masks the symptom. Check `journalctl -t deuswatch-watchdog` occasionally, because
repeated recoveries mean something underneath needs fixing rather than restarting.

**It records the autopsy before it resuscitates.** This was learned the hard way: recovering the
worker means `docker compose up -d`, which creates a *new* container, and the dead one's exit code,
OOM flag and logs go with it. Several outages here were never explained for exactly that reason, the
fix kept destroying its own evidence. So each recovery now logs the dead container's
`exit`/`oom`/`restarts` and its final 25 log lines to the journal first, and distinguishes a container
that *exited* from one that was *removed*, which have completely different causes. The diagnostics are
best-effort and can never block the restart.

#### Auto-restarting an unhealthy container (not shipped, on purpose)

The healthcheck marks a container unhealthy but does not restart it, and Docker Compose has no
native "restart when unhealthy". Closing that last row of the table needs a helper container that
watches for unhealthy containers and restarts them, which means **giving that container the Docker
socket**.

A container holding the Docker socket is effectively **root on the host**: it can start containers,
mount host paths, and read anything. On a security platform that is not a reasonable default, so
nothing like it ships in `docker-compose.yml`. The worker's healthcheck still surfaces the condition
(`docker compose ps` shows `unhealthy`) without handing anything that access.

It is also rarely the thing that saves you. Every worker outage observed on a live deployment so far
was either a process exit (already covered by `restart: unless-stopped`) or a failed deploy that left
no container at all (which an auto-restarter cannot help with either). Add one only if you actually
observe a worker sitting `unhealthy` without ever exiting.

If you decide you need it, the common choice is `willfarrell/autoheal` (MIT, widely used). The worker
already carries the `autoheal: "true"` label it looks for, so it is one service away:

```yaml
  autoheal:
    image: willfarrell/autoheal@sha256:<pin-a-digest-here>
    environment:
      AUTOHEAL_CONTAINER_LABEL: autoheal
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    restart: unless-stopped
```

**Pin it by digest, not by tag.** A tag can be re-pushed by its owner; for something with
host-root-equivalent access that difference matters. Get the digest with:

```bash
docker inspect --format '{{index .RepoDigests 0}}' willfarrell/autoheal:1.2.0
```

Mounting the socket read-only does not help, by the way: the Docker API is a write API over that
socket either way.

### Disk watermark

When `STORAGE_BUDGET_GB` is set, the worker watches the log database against it:

- At `STORAGE_ALERT_PERCENT` (default `85`) it notifies through the configured channels.
- At `STORAGE_JANITOR_PERCENT` (default `90`) it **drops the oldest event chunks** and raises a
  high-severity `selfhealth` alert on every trigger, losing the oldest history is preferable to
  PostgreSQL hitting a full disk, but it must never happen quietly.

Both are inert while `STORAGE_BUDGET_GB` is `0`, which is the default.

## How to use

1. **Agents** page, the status pill per endpoint (`online` / `degraded` / `disconnected` /
   `stale` / `never connected`), with the agent's self-reported detail on hover.
2. **Dashboard → Agents widget**: the same states, sorted so the actionable ones come first.
3. **The red banner** appears by itself when the worker stops. It carries the command to bring it
   back, and clears within 30 seconds of the worker's first heartbeat.
4. **Alerts**: `selfhealth` alerts sit alongside attack alerts, searchable and ticketable like
   any other.

### Testing that it actually works

Worth doing once, because an alarm nobody has ever seen fire is an assumption, not a control:

```bash
docker compose -f deploy/docker-compose.yml stop worker
```

The banner should appear within about two minutes. Start it again and it clears within 30
seconds. (`stop` is deliberate: it is the one case that must NOT self-restart, since an operator
stopping a component on purpose should stay stopped. To watch the recovery path instead, use
`docker compose kill worker`, which exits the process and should come back on its own.)

Checking the healthcheck itself:

```bash
docker compose -f deploy/docker-compose.yml ps worker
```

It should read `Up (healthy)`. `Up` on its own means the image predates the healthcheck.

## Endpoints & storage

| What | Where |
|---|---|
| Service liveness | `GET /api/system/services` (permission `view_dashboard`) |
| Heartbeat table | `service_heartbeats` (migration `000062`): one row per component, upserted |
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
| `WORKER_STALL_LIMIT` | `3m` | Silence before the worker's watchdog exits the process for a clean auto-restart, and the point at which `/healthz` starts failing |

The worker's own heartbeat interval (30s) and the API's staleness threshold (100s) are constants,
not environment variables. They are a matched pair, and letting them drift apart in configuration
would produce either false alarms or a blind spot.

## Known gaps

Stated rather than left to be discovered:

- **The gateway and the api are not watched this way.** Only the worker writes a heartbeat. Their
  failure is at least self-announcing, agents log connection errors and the UI stops loading,
  whereas the worker's is silent, which is why it came first.
- **No notification on worker death.** The banner is in-app only. Routing it to Telegram/email
  would mean the notifier surviving the component it reports on, which needs more care than a
  heartbeat read.
