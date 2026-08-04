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

- **`sudo nft list tables` shows only the defaults, no `deuswatch`**: check the agent log
  for a line like `agent: firewall synced N blocked IP(s) into nft set deuswatch/blocklist`.
  No such line means either (a) the integration is disabled, (b) the agent's CN isn't in
  the scope, or (c) the poll hasn't fired yet — wait 30 s.
- **`agent: apply blocklist: exit status 1`** — usually a permission problem. Verify the
  agent runs as root (`systemctl show deuswatch-agent -p User`) and that `nft` is on PATH.
- **A block set on the manager doesn't remove from the host** — the reconcile is atomic
  (flush + re-add), so a removed IP is gone within the next poll. If it persists longer
  than that, `nft list set inet deuswatch blocklist` on the host will tell you what's
  actually loaded; likely another process is re-adding it.
