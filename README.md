<div align="center">

# DeusWatch

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
