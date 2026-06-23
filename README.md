<div align="center">

# DEUSWATCH

**All-in-One, Open Source, Self-Hosted Security Platform.**

SIEM · IDS/IPS · lightweight SOAR · CTI enrichment · LLM-based analysis — in one lightweight, modular system.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Phase%201–3%20complete-green.svg)]()

</div>

---

> ⚠️ **Status: active development.** Phases 1–3 are implemented end-to-end; not yet hardened for production.

## What is DeusWatch?

DeusWatch combines security detection and response in a single package you can run with one
`docker compose up` command. It is beginner-friendly by default, yet fully customizable for
SOC professionals.

Core principle: **don't reinvent the wheel.** We build on mature standards (Sigma rules, the
CrowdSec bouncer protocol, PostgreSQL, NATS) and focus on the integration layer and user
experience that no single vendor packages together.

## Features (roadmap)

| Phase | Scope | Status |
|---|---|---|
| **Phase 1** | Linux agent, mTLS ingest, gateway + normalization, NATS, Postgres+TimescaleDB, Sigma detection (SSH brute force, etc.) + auto MITRE labeling, API + RBAC + audit log, base Web UI | ✅ |
| **Phase 2** | Windows/macOS agent, CTI enrichment (AbuseIPDB/OTX/GeoIP), response engine (nftables/Mikrotik/CrowdSec LAPI), TOTP 2FA, notifications (Telegram/email/webhook) | ✅ |
| **Phase 3** | LLM worker (Claude/heuristic), automated reports, community blocklist | ✅ |
| Phase 4 | Android agent, rule/integration marketplace, Helm chart | planned |

## Architecture

```
Agent (Go) ──mTLS──> Ingest Gateway ──> NATS JetStream ──> Worker (detect/enrich/respond/llm)
                                                                  │
                                          PostgreSQL 16 + TimescaleDB + pgvector
                                                                  │
                                              API Server (Go) ──> Web UI (React + Vite)
```

Full design details: see [DeusWatch.md](DeusWatch.md).

## Quick start

One command brings up the whole stack (db, NATS, cert generation, API, gateway, worker, web UI):

```bash
git clone https://github.com/FirdausYudha/DeusWatch.git
cd DeusWatch
docker compose -f deploy/docker-compose.yml up -d --build
```

- **Web UI:** http://localhost:5173 · **API:** http://localhost:8080
- **Default login:** `admin` / `thewatcher` (change via `ADMIN_PASSWORD`)
- Self-registration is available on the login page (new accounts get the viewer role).

## Deploying agents

In the UI go to **Agents → + Add agent**, pick the OS/architecture, set **Manager host** to
the address agents will reach (the LAN IP for cross-host, e.g. `192.168.1.10:8080`), and copy
the generated one-liner. It downloads the agent, enrols with a one-time token, installs an
auto-start service, and connects — e.g. on Linux:

```bash
curl -fsSL http://<manager>:8080/api/agent/install.sh | sudo MANAGER=<manager> TOKEN=<token> NAME=<name> sh
```

The manager must allow inbound **8080** (enrol/install) and **8443** (gateway, mTLS):

- Linux manager: `sudo ufw allow 8080,8443/tcp` (if `ufw` is active)
- Windows manager: `New-NetFirewallRule -DisplayName "DeusWatch" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080,8443`

Agents authenticate the manager by the deployment's **private CA**, not by hostname/IP, so
cross-host deployments work without per-IP certificate tweaks. To additionally pin the
manager's IP into the server certificate SAN (optional), set `MANAGER_IP` in `deploy/.env`
before first start (e.g. `MANAGER_IP=192.168.1.10`); changing it later means regenerating
certs (delete `deploy/certs/*` or run certgen with `-force`) and re-enrolling agents (a new
CA invalidates old certs).

### Troubleshooting an offline agent

Online status is driven by the heartbeat to the gateway (`:8443`). If an agent shows
**offline** while `systemctl status deuswatch-agent` looks healthy, check its logs:

```bash
sudo journalctl -u deuswatch-agent -n 30 --no-pager
```

- `connection refused` / timeout → the manager's firewall is blocking 8443, or the wrong `MANAGER`/host.
- `x509: certificate signed by unknown authority` → the agent enrolled against a different CA; re-enrol after regenerating certs.

## Tech stack

Go · PostgreSQL + TimescaleDB · pgvector · NATS JetStream · Sigma · React + Vite + Tailwind ·
Docker · LLM provider via the official Anthropic SDK (Claude).

## Security

A security system that isn't secure is an irony. mTLS is required, RBAC from day one,
encrypted secrets, append-only audit log. See [SECURITY.md](SECURITY.md) for the
responsible-disclosure policy.

## License

[AGPL-3.0](LICENSE) — free to self-host forever, anti vendor lock-in.

## Support

♥ Like DeusWatch? Consider supporting via the **Sponsor** button on this repo
(Saweria for Indonesia, Ko-fi for international).
