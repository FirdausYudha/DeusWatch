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

Only when it acts, so a healthy system stays quiet:

```
deuswatch-watchdog: worker state=missing health=none, bringing it back
deuswatch-watchdog: worker recovered
```

Read the history with `journalctl -t deuswatch-watchdog`. Repeated recoveries mean something is
genuinely wrong and the watchdog is only masking it: check `docker compose logs worker` for the
reason rather than leaving it to flap.

## Scope

It only ever touches the `worker` service. The database, gateway and api are left alone, because a
watchdog that restarts things it does not understand causes more outages than it prevents.
