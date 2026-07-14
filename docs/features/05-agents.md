# 5. Agents

Register endpoints, generate the one-line installer, monitor online/offline status, revoke,
and push config. This is the **only** feature that uses the Gateway (mTLS), not just the API.

## How it works

- **Enroll**: the wizard creates a single-use token. The agent exchanges it (over the API,
  `9080`) for a unique **client certificate** (mTLS). No plaintext mode.
- **Ship**: the agent tails its sources and streams logs to the **Gateway** over **mTLS
  (`9443`)** → NATS → worker. A periodic **heartbeat** updates `last_seen_at`.
- **Health states** (self-monitoring): the worker recomputes each agent's state every 30s -
  `online` → `degraded` (heartbeat arrives but the agent reports a problem, e.g. its offline
  buffer is piling up because log shipping fails) → `disconnected` (~3 heartbeats missed,
  configurable via `AGENT_DISCONNECT_AFTER`) → `stale` (silent > `AGENT_STALE_AFTER`, default
  24h). The transition to **disconnected raises a high-severity `selfhealth` alert** through
  the normal pipeline (dashboard + Telegram/email): a dead agent can mean a crash - or an
  attacker disabling it to erase their tracks (MITRE T1562.001). Recovery is logged as an
  info event. **Revoke** flips a flag so the gateway rejects that cert; the agent then
  self-uninstalls.
- **Revoked entries stay in the list on purpose** - the old mTLS certificate remains
  cryptographically valid until it expires, and the revoked row is exactly what keeps the
  gateway rejecting it (deleting the row would let the old cert back in). The name is NOT
  blocked though: **enrolling again with a revoked agent's name takes over that entry**
  (new certificate, un-revoked, health reset, config kept), and the superseded certificate
  stays locked out via a **serial pin** - the gateway checks the certificate serial, not
  just the CN. An *active* agent's name stays taken until you revoke it.
- Agent binaries (Linux/Windows, amd64/arm64) are cross-compiled and served by the API's
  one-line installer - no host build step.

## How to use

1. **Agents → + Add agent** → pick OS (Linux / Windows).
2. Set **Manager host** to the address agents reach (LAN IP for cross-host, e.g.
   `192.168.1.10:9080`). A one-time token is generated automatically.
3. Copy the one-liner and run it on the endpoint - it downloads the agent, enrolls, installs an
   auto-start service, and connects. Example (Linux):
   ```bash
   curl -fsSL http://<manager>:9080/api/agent/install.sh | sudo MANAGER=<manager> TOKEN=<t> NAME=<n> API_PORT=9080 GW_PORT=9443 sh
   ```
4. The list shows each agent's OS, config version, last-seen, and online dot. **Revoke** to
   decommission (agent self-uninstalls).

## Uninstalling / cleaning up an agent

Preferred: **Revoke** the agent in the UI - on its next heartbeat the gateway replies 410
Gone and the agent self-uninstalls (removes its binary, service, certs and buffer). You can
also trigger a clean removal locally:

```bash
# Linux                                   # Windows (elevated PowerShell)
sudo deuswatch-agent -uninstall           & "C:\Program Files\DeusWatch\deuswatch-agent.exe" -uninstall
```

If a service is stuck or the binary is already gone, remove the pieces manually:

```bash
# Linux
sudo systemctl disable --now deuswatch-agent
sudo rm -f /etc/systemd/system/deuswatch-agent.service && sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/deuswatch-agent
sudo rm -rf /etc/deuswatch /var/lib/deuswatch     # certs + config + offline buffer
```

```powershell
# Windows (elevated)
Stop-Service DeusWatchAgent -Force -ErrorAction SilentlyContinue
sc.exe delete DeusWatchAgent
Remove-Item -Recurse -Force 'C:\Program Files\DeusWatch','C:\ProgramData\DeusWatch'
Remove-NetFirewallRule -DisplayName 'DeusWatch agent (outbound)' -ErrorAction SilentlyContinue
```

What each path holds: the **binary** (`/usr/local/bin` · `C:\Program Files\DeusWatch`),
the **certs + config** and **offline buffer** (`/etc/deuswatch` + `/var/lib/deuswatch` ·
`C:\ProgramData\DeusWatch`, which also holds the Windows agent log). Removing the certs is
what fully de-enrolls the host; re-installing later issues a fresh certificate.

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/agents` | agent list | `view_dashboard` |
| `POST /api/agents/tokens` | new enroll token | `manage_agents` |
| `POST /api/agents/{id}/revoke` | revoke a cert | `manage_agents` |
| `PUT /api/agents/{id}/config` | push a config | `manage_agents` |
| `GET /api/agent/install.sh` / `.ps1` / `install-info` / `binary/{os}/{arch}` | public installer + binaries | none (token is the credential) |
| `POST /v1/logs`, `/v1/heartbeat` (Gateway) | log ingest + liveness (mTLS) | client cert |

Frontend: [`web/src/agents/`](../../web/src/agents/). Backend:
[`internal/enroll/`](../../internal/enroll/), [`internal/gateway/`](../../internal/gateway/),
agent in [`cmd/agent/`](../../cmd/agent/).

## Ports / tech

- Enroll/install/binary: **API `9080`** (HTTP). Log ingest + heartbeat: **Gateway `9443`**
  (mTLS). Open both inbound on the manager: `ufw allow 9080,9443/tcp`.
- Language: Go (agent is a single static binary; gateway/enroll are Go).

## Variables

- `MANAGER_IP` in `deploy/.env` - pins the manager IP into the mTLS server-cert SAN for
  cross-host agents (set before first start; changing it means regenerating certs + re-enroll).
- Ports agents use: `DEUSWATCH_API_PORT` (9080) and `DEUSWATCH_GATEWAY_PORT` (9443) - the
  wizard reads them automatically so the generated command is correct.
- Per-agent **sources** (which logs to tail) are pushed via `PUT /api/agents/{id}/config`.
  Built-in datasets: `sshd`, `syslog`, `firewall`, `web`/`nginx`/`apache`, `fim`, `windows-*`,
  and `suricata` (Suricata/Snort EVE JSON - see [docs/suricata.md](../suricata.md) for the
  Emerging Threats ET Open/ET Pro network-IDS integration).
- **Custom decoders**: to support any OTHER log source without code, add a regex decoder under
  [`decoders/`](../../decoders/README.md) that sets a category and extracts fields; then write
  rules scoped to that category. The gateway applies them as a fallback for datasets with no
  built-in decoder.
