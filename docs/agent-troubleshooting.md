# Agent troubleshooting

Practical answers to "the agent looks fine but I'm not seeing what I expect." Ordered by how often
each one is the real cause.

## "The agent is online but no logs / no attacks show up"

The single most common confusion. **The agent being green in the Agents page does not mean logs are
flowing.** Two independent things are happening:

- **Heartbeat** — a small "I'm alive" ping every 30s over its own path. This is what colours the
  agent green and sets *last seen*.
- **Log shipping** — the actual events. Separate path, separate failure modes.

So an agent can be green while shipping nothing. When events are missing, check which of the causes
below applies.

### 1. The agent isn't watching a source that would capture it

The manager's pushed monitoring config **replaces** the agent's default sources entirely. If you
configured the agent to watch only a FIM path (e.g. `/var/www/html`), then the default log
sources — SSH, syslog, web, firewall — are **not running**, and nothing SSH/scan/brute-force will
ever appear, no matter how much of it hits the box.

Check what the agent is actually watching:

```bash
journalctl -u deuswatch-agent | grep "source:"
#   source: dataset=web type=fim path=/var/www/html      <- FIM only, no log tailing
```

Each kind of attack needs a matching source. Add them in the manager's Agents page:

| You want to see | Add source | Path | Note |
| --- | --- | --- | --- |
| SSH brute-force | `sshd` (file) | `/var/log/auth.log` | Debian/Ubuntu. RHEL/Fedora use journald — use a `journald` source instead |
| Web scanning / defacement | `web` (file) | `/var/log/nginx/access.log` | apache: `/var/log/apache2/access.log` |
| Port scans | `firewall` (file) | `/var/log/ufw.log` | **requires** `ufw logging on` (or an iptables/nftables LOG rule) |
| File integrity / ransomware | `web` (fim) | `/var/www/html` | change detection, not log tailing |

Saving bumps the config version; the agent restarts itself to apply it.

### 2. The log source is watching a file that is empty or absent

A `file` source whose path doesn't exist yet won't kill the agent (it waits for the file to appear),
but it also produces nothing until the file exists and something writes to it. Verify:

```bash
ls -la /var/log/auth.log /var/log/nginx/access.log /var/log/ufw.log
tail -f /var/log/auth.log     # are new lines actually being written?
```

### 3. The manager (gateway) is unreachable

If shipping fails, events are buffered to disk and re-sent later; the heartbeat reports *degraded*.
Look for:

```bash
journalctl -u deuswatch-agent | grep -Ei "buffered|heartbeat failed|connection refused"
```

`connection refused` to the gateway means the manager side is down or not listening on its port
(default `9443`). Occasional failures are fine (the agent retries and buffers); constant failures
mean the gateway is down.

## Confirm the pipeline actually works

Two quick end-to-end tests.

**FIM (proves agent → gateway → manager):**

```bash
echo "// test $(date)" >> /var/www/html/index.php
```

A FIM event should appear on the dashboard (range 1h) within ~15s.

**Attack detection (after adding the `sshd` source):** from another machine,

```bash
for i in $(seq 5); do ssh baduser@YOUR-SERVER; done   # type a wrong password each time
```

The source IP should surface in **Top source IPs** / **Suspicious IPs**.

## "Is the network actually quiet, or is DeusWatch just not looking?"

Ask the box directly — this is ground truth, independent of DeusWatch:

```bash
grep -c "Failed password" /var/log/auth.log            # this rotation period
zcat -f /var/log/auth.log.1 | grep -c "Failed password" # previous period
grep "Failed password" /var/log/auth.log | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  | sort | uniq -c | sort -rn | head                   # top attacker IPs
```

If those counts are healthy but the dashboard is empty, the network is fine and DeusWatch simply
isn't watching that log (see the first section). Note counts are per **rotation period**: a weekly
`auth.log.1` naturally has ~7× the entries of a two-day-old `auth.log`.

## "Inotify Instance Capacity Low" (or FIM fell back to poll-only)

FIM's real-time detection uses the kernel's inotify. There are two per-user limits, often confused:

- `fs.inotify.max_user_instances` — number of inotify *instances*. **This** is what the
  "Instance Capacity Low" warning is about.
- `fs.inotify.max_user_watches` — number of watched *paths*.

**DeusWatch is almost never the cause of instance exhaustion.** The agent creates exactly **one**
inotify instance per FIM source and adds many watches to that single instance (the efficient
pattern). Instance exhaustion comes from many separate apps each opening their own — on a desktop or
dev box: editors (VS Code is a heavy user), file indexers, browsers, node/webpack dev servers,
Docker.

**It is safe** — nothing crashes. If inotify is exhausted when the agent starts, FIM logs it and
falls back to **poll-only**: changes are still detected, just up to the scan interval (≥ 1 minute)
late instead of instantly. The tell in the log:

```bash
journalctl -u deuswatch-agent | grep -i 'real-time'
#   real-time watch active (fsnotify) + safety poll              <- healthy
#   real-time watch UNAVAILABLE, falling back to poll-only ...   <- degraded
```

> Grep for `real-time`, **not** `fsnotify` — the degraded line doesn't contain the word "fsnotify",
> so grepping that would hide the very case you're looking for. And if this returns **nothing at
> all**, the agent probably has no FIM source configured (the line only prints for a `fim` source) —
> confirm with `journalctl -u deuswatch-agent | grep "source:"`.

Raise the limits so real-time detection stays available (and other apps stop warning):

```bash
sudo tee /etc/sysctl.d/60-deuswatch-inotify.conf <<'EOF'
fs.inotify.max_user_instances = 512
fs.inotify.max_user_watches = 524288
EOF
sudo sysctl --system
sudo systemctl restart deuswatch-agent   # let FIM re-claim real-time
```

See who is consuming instances:

```bash
find /proc/*/fd -lname 'anon_inode:inotify' 2>/dev/null | cut -d/ -f3 | sort | uniq -c | sort -rn | head
```

## Log rotation

The file tailer follows rotation automatically: when `logrotate` renames a file away and a fresh one
takes its place, the agent drains the old file, then reopens and follows the new one (both the
default rename+create and `copytruncate` styles). A file that doesn't exist yet is waited for rather
than treated as a fatal error. No agent restart is needed across a rotation.
