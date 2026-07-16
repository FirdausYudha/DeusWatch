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

Restart the agent. It installs an audit watch rule on each FIM directory and tails the audit log:

```
agent: who-data active (audit watch on 1 path(s), key=deuswatch_fim)
```

Now change a monitored file and open the alert — the **File change** block shows
`changed by <process> (pid N) as user <user> · who-data`.

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
