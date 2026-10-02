# Worker watchdog (host-side)

Guarantees the detection worker comes back without anyone logging in, including the case no
in-container mechanism can handle: **the container not existing at all**.

## Why this exists

Each in-container mechanism has a blind spot:

| Mechanism | Covers | Blind spot |
|---|---|---|
| `restart: unless-stopped` | The process exits (crash, OOM, watchdog exit) | A container that does not exist |
| The in-process watchdog | A wedged DB path, by exiting on purpose | A process too wedged to run its own goroutine |
| An autoheal container | Containers marked unhealthy | Cannot recreate a missing container, and needs the Docker socket (root-equivalent) |

The gap they share is the one that actually took this deployment down: a failed deploy removed the
old worker container and never created the new one, so there was nothing left to restart.

This watchdog runs on the host as a systemd timer. It covers **missing, exited, restarting and
unhealthy** alike, adds no container, and gives nothing the Docker socket.

## Install

```bash
sudo install -m 0755 deploy/systemd/deuswatch-watchdog.sh /usr/local/bin/deuswatch-watchdog.sh
sudo install -m 0644 deploy/systemd/deuswatch-watchdog.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/deuswatch-watchdog.timer   /etc/systemd/system/
```

If your checkout is not at `/home/deus/Document/DeusWatch`, edit `DEUSWATCH_DIR` in the `.service`
file first.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now deuswatch-watchdog.timer
```

## Verify

Run it once by hand; it should do nothing and exit cleanly when the worker is healthy:

```bash
sudo systemctl start deuswatch-watchdog.service
systemctl status deuswatch-watchdog.service
```

Then prove it actually recovers, which is worth doing once because an untested recovery path is an
assumption, not a control:

```bash
docker rm -f deuswatch-worker-1     # simulate the worst case: the container is GONE
journalctl -t deuswatch-watchdog -f # watch it come back within a minute
```

## What it logs

Only when it acts, so a healthy system stays quiet. Each recovery records **why** the worker was
gone before bringing it back, because `docker compose up -d` creates a *new* container and the dead
one's exit code, OOM flag and logs disappear with it. Without this, every recovery destroyed the only
evidence of what it was recovering from:

```
deuswatch-watchdog: worker state=exited health=none, bringing it back
deuswatch-watchdog: post-mortem: exit=137 oom=true err= restarts=4 finished=2026-10-02T09:03:11Z
deuswatch-watchdog: last-log: <the worker's final 25 lines>
deuswatch-watchdog: worker recovered
```

Read the history with `journalctl -t deuswatch-watchdog`. The post-mortem line is what tells the two
very different failures apart:

| Line | Meaning | What to do |
|---|---|---|
| `state=exited` + `oom=true` | The kernel killed it for memory | Raise the worker's memory limit, or find what allocates |
| `state=exited` + `exit=1` | It exited on purpose or crashed; `last-log:` says which | Read the last log lines |
| `state=unhealthy` | Alive but wedged past `WORKER_STALL_LIMIT` | Read the last log lines |
| `container was REMOVED` | Something deleted the container: a failed deploy, a manual `docker rm`, or a `compose` recreate | Not a worker fault. Check what ran at that time |

Repeated recoveries mean something underneath is genuinely broken and the watchdog is only masking
it. A `REMOVED` line right after you deployed or ran the recovery test below is expected.

## Scope

It only ever touches the `worker` service. The database, gateway and api are left alone, because a
watchdog that restarts things it does not understand causes more outages than it prevents.
