# 5. Agents

Register endpoints, generate the one-line installer, monitor online/offline status, revoke,
and push config. This is the **only** feature that uses the Gateway (mTLS), not just the API.

## How it works

- **Enroll**: the wizard creates a single-use token. The agent exchanges it (over the API,
  `9080`) for a unique **client certificate** (mTLS). No plaintext mode.
- **Ship**: the agent tails its sources and streams logs to the **Gateway** over **mTLS
  (`9443`)** → NATS → worker. A periodic **heartbeat** updates `last_seen_at`.
- **Online status** = heartbeat within the last 90s (computed in the UI). **Revoke** flips a
  flag so the gateway rejects that cert; the agent then self-uninstalls.
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
