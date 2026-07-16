# Who-data: who changed the file (FIM attribution)

Plain FIM tells you a file changed and (in DeusWatch) *which lines* changed. **Who-data** adds
the missing piece: **which process and user made the change** — so a defacement alert can name
`php-fpm as user www-data` or `vim as user root`, not just the path.

DeusWatch surfaces who-data from two sources:

- **The DeusWatch agent (native, Linux)** — via the Linux **audit** subsystem. This page.
- **A Wazuh feed** — Wazuh's syscheck who-data (`data.audit.process`) is mapped automatically
  when alerts arrive through the [webhook](wazuh-webhook.md) or [OpenSearch pull](opensearch.md).

## Enable it on the agent (Linux)

Who-data uses the kernel audit subsystem, so it needs **root** and **auditd** installed, and it
is **opt-in** (it adds an audit rule to the host):

```bash
sudo apt install -y auditd        # or: dnf install audit
# In the agent's environment (systemd unit / EnvironmentFile):
AGENT_WHODATA=1
```

Restart the agent (`systemctl restart deuswatch-agent` — a plain `start` won't re-read the env).
It installs an audit watch rule on each FIM directory and tails the audit log:

```
agent: who-data active (audit watch on 1 path(s), key=deuswatch_fim)
```

Now change a monitored file. The **File change** block shows
`changed by <process> (pid N) as user <user> · who-data` — on both the raw `file_modified`
event and the labeled alert (the alert carries the actor as of **v1.7.1**; before that, only the
raw `file_modified` event did).

### It unmasks sudo

The user is the **login user** (audit `auid`), not the effective uid. So a change made with
`sudo` is attributed to the human who logged in — e.g. a file edited via `sudo` by user `deus`
shows `as user deus(1001)`, not `root`. That's usually exactly who you want to hold accountable.

## How it works

For each FIM source, the agent runs `auditctl -w <dir> -p wa -k deuswatch_fim`, then tails
`/var/log/audit/audit.log` (overridable with `AGENT_AUDIT_LOG`). It correlates each audit event
(`SYSCALL` + `PATH` records) to the file path and remembers the actor for a short window; when the
FIM scan reports a change, the most recent actor for that path is attached (process name, exe, pid,
login user, and the syscall). Reading the log — rather than the audit netlink socket — avoids
contending with auditd, which owns that socket.

## Honest limitations

- **Linux only.** Windows who-data (SACL-based) is not implemented; FIM still works on Windows,
  just without the "who". macOS likewise.
- **Needs root + auditd.** Without them the agent logs `who-data disabled: …` and continues with
  normal FIM (no attribution).
- **Correlation is best-effort.** The actor is matched by path within a short time window. Under
  very heavy churn on the same path, or if auditd drops records (backlog limit), an attribution can
  be missed or, rarely, point at the wrong recent writer. The file-change detection itself is never
  affected — only the "who" annotation.
- It installs an audit rule on the host (removed on reboot, or with `auditctl -W <dir> -p wa -k
  deuswatch_fim`). This is the same mechanism Wazuh's who-data uses.

## Troubleshooting

**`who-data disabled: no audit rules could be installed … (Rule exists)`** — the audit rule is a
*persistent kernel rule*, so it survives an agent restart. On **v1.7.0** the agent mistook the
"Rule exists" reply for a failure and disabled who-data after the first restart. Fixed in
**v1.7.1** (a pre-existing rule now counts as success). If you're on an older agent, either
upgrade, or clear the rule once so the agent re-adds it fresh:

```bash
sudo auditctl -W /var/www/html -p wa -k deuswatch_fim   # remove the stale rule
sudo systemctl restart deuswatch-agent                  # agent re-adds it and activates who-data
```

**`user_name` shows but `process_name` doesn't (on an alert)** — the labeled alert only carries
the process from **v1.7.1** on; update the worker (`./update.sh`). The raw `file_modified` event
carries both from v1.7.0. Verify audit is capturing the actor at all with:

```bash
sudo ausearch -k deuswatch_fim -ts recent | grep -E 'comm=|name=' | tail
```

**Nothing at all** — check `sudo auditctl -l` lists the `-w <dir> … -k deuswatch_fim` rule and
that `sudo systemctl status auditd` is active.
