# Agent-side firewall (nftables) integration

Enable this to have DeusWatch push its active block list onto each Linux endpoint's own
nftables set, so the endpoint drops packets from banned IPs even before they reach any
service. As of **v2.11.0** the manager's integration is the source of truth: no per-host
env-var dance required.

## Setup

1. **Integrations → Add → Linux firewall — nftables (agent-side)**.
2. Fields:
   - **nft table** (optional, default `deuswatch`) — the nftables table the agent creates.
   - **nft set** (optional, default `blocklist`) — the set inside that table.
   - **Apply to agents** (optional) — comma-separated agent names to scope the rules to.
     Blank means every enrolled agent.
3. Save with **Enabled** ticked. The agent polls every 30 s, so allow up to ~30 s for the
   first sync to appear on the host.
4. On the host you should see the table materialise:
   ```
   $ sudo nft list tables
   table inet deuswatch
   $ sudo nft list set inet deuswatch blocklist
   table inet deuswatch {
     set blocklist {
       type ipv4_addr
       elements = { 1.2.3.4, 5.6.7.8 }
     }
   }
   ```

## Requirements on the endpoint

- Linux + `nft` binary present (`apt-get install nftables`).
- Agent runs as root (needed for `nft add table` and related). If you use systemd, the
  installer already deploys a unit that runs as root.

## Why "Apply to agents" matters

An empty scope means the manager pushes the enable flag to **every** agent — including
Windows hosts, which will simply ignore it (nftables is Linux-only). When you scope to
specific names (e.g. `linux2, web-01`), only those receive the enable flag; other agents
see `enabled=false` and leave their firewall untouched.

Matches are **exact** and case-insensitive against the agent's certificate CN (what shows
up in the Agents list as the agent name).

## Env-var overrides (backwards compatibility)

Pre-v2.11 deployments activated this via env vars on the agent process. Those still work
and take precedence over the server envelope:

| Env var | Effect |
|---|---|
| `AGENT_FIREWALL=nftables` | Force the firewall loop ON even when the server says `enabled=false`. Useful for air-gapped hosts or IaC-managed installs. |
| `NFT_TABLE=<name>` | Override the table name the server sent. |
| `NFT_SET=<name>` | Override the set name the server sent. |

## Teardown

Disabling the integration in the UI stops the agent from ADDING to the set on the next
poll, but the existing table/rules are **not** removed — cleanup is a manual step, so an
operator toggling the integration off doesn't accidentally unblock everyone:

```bash
sudo nft delete table inet deuswatch
```

## Troubleshooting

### The `deuswatch` table never appears on the agent host

Work through this checklist in order — the four common failure modes below cover ~all
"UI says enabled, host shows nothing" reports.

**1. Is the manager running v2.11.0+?**

Pre-v2.11 the UI stored the config but never delivered it to the agent — this doc's
premise assumes the fix that lets the manager push. On the manager host:

```bash
docker compose -f deploy/docker-compose.yml exec api /app -version 2>/dev/null || \
  docker compose -f deploy/docker-compose.yml logs api | grep "listening on"
```

If the reported version is older than 2.11.0, pull `main`, `docker compose up -d --build
gateway api worker`, then continue.

**2. Is the AGENT running v2.11.0+?**

Server-side changes alone are not enough — the agent binary must parse the new
`{enabled, table, set, ips}` response envelope (pre-v2.11 it only reads `ips` and gates
activation on the `AGENT_FIREWALL` env var). On the agent host:

```bash
sudo systemctl restart deuswatch-agent   # if unit is already installed
# or download & reinstall from the manager's Agents page → Install script
```

Check the agent log for a v2.11-era line (any of these confirms the new binary):

```bash
sudo journalctl -u deuswatch-agent -n 200 | grep -E "firewall synced|apply blocklist"
```

**3. Does the manager's gateway say the agent is matched?**

The gateway logs one line per (agent, decision) transition, plus a heartbeat every 60 s
per CN. On the manager host:

```bash
docker compose -f deploy/docker-compose.yml logs gateway | grep "nftables push"
```

Interpret what you see:

- `enabled=true scope="linux2" ips=N reason="matched integration nftables"` → the agent
  IS receiving the push; problem is on the endpoint (jump to #4).
- `enabled=false ... reason="no enabled nftables_agent integration"` → toggle **Enabled**
  in the Integrations panel.
- `enabled=false ... reason="agent_scope did not match (scope=linux2)"` → your **Apply to
  agents** value doesn't match the agent's CN. Names are **exact** match, case-insensitive.
  Check the Agents page for the CN as DeusWatch enrolled it — hostnames with dots
  (`linux2.local`) or a suffix from your enrollment token will NOT match `linux2`.
- No line at all after ~30 s → the agent is not reaching the gateway. Check
  `/v1/heartbeat` in the gateway log; if it's absent too, the agent-manager mTLS link
  itself is down.

**4. Agent runs, gateway confirms push, but `nft list tables` is still empty.**

Almost always a permissions problem on the endpoint.

```bash
systemctl show deuswatch-agent -p User
# → User=root  (correct)
# → User=deuswatch  (WRONG — nftables needs CAP_NET_ADMIN, easiest as root)

which nft
# must resolve; on minimal Ubuntu run: sudo apt-get install nftables
```

If both look right, check the agent's own error output:

```bash
sudo journalctl -u deuswatch-agent -n 100 | grep -E "apply blocklist|firewall"
```

A line like `agent: apply blocklist: exit status 1` almost always means either `nft` isn't
on `$PATH` for the service, or another firewall manager (ufw, firewalld) is rejecting the
add. In that case, run the equivalent by hand as root to see the real error:

```bash
sudo nft add table inet deuswatch
sudo nft add set inet deuswatch blocklist '{ type ipv4_addr; }'
```

### A block set on the manager doesn't remove from the host

The reconcile is atomic (flush + re-add), so a removed IP is gone within the next poll.
If it persists longer than that, `nft list set inet deuswatch blocklist` on the host will
tell you what's actually loaded; likely another process (ufw, fail2ban, your own script)
is re-adding it.
