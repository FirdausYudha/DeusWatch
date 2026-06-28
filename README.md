<div align="center">

# DEUSWATCH

**All-in-One, Open Source, Self-Hosted Security Platform.**

SIEM · IDS/IPS · lightweight SOAR · CTI enrichment · LLM-based analysis — in one lightweight, modular system.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Phase%201–5%20complete%20·%20detection%20Linux--tested-green.svg)]()
[![Made with Go](https://img.shields.io/badge/Go-backend-00ADD8.svg)]()
[![Web: React + Vite](https://img.shields.io/badge/Web-React%20%2B%20Vite-61DAFB.svg)]()

[Features](#features) · [Integrations](#integrations) · [Quick start](#quick-start) · [Documentation](#documentation) · [Support ♥](#support)

</div>

---

> ⚠️ **Status: active development.** Phases 1–5 are implemented (ingest, detection, enrichment,
> response, FIM + hash reputation, endpoint remediation, AI reports). Detection & response are
> verified end-to-end on Linux; Windows/macOS detection is still in progress. Functional for labs
> and self-hosting; not yet hardened for production.

## What is DeusWatch?

DeusWatch combines security detection and response in a single package you can run with one
`docker compose up` command. It is beginner-friendly by default, yet fully customizable for
SOC professionals.

Core principle: **don't reinvent the wheel.** We build on mature standards (Sigma rules, the
CrowdSec bouncer protocol, PostgreSQL, NATS) and focus on the integration layer and user
experience that no single vendor packages together.

## Features

**Collect → Detect → Enrich → Decide → Respond**, with a human-friendly UI over every step.

- **Ingest** — lightweight Go agents ship logs over mTLS (Linux/Windows/macOS); a gateway normalizes them into a common event schema on NATS JetStream.
- **Detect** — [Sigma](https://github.com/SigmaHQ/sigma) rules, both single-event and aggregation/correlation (e.g. SSH brute force = N failures from one IP). Rules are **DB-backed and fully managed from the UI** (Wazuh-style): browse, edit, toggle, add or delete — built-ins are seeded on first start, custom rules validated on save. Alerts are auto-labeled with **MITRE ATT&CK** technique/tactic.
- **Enrich** — source IPs scored with CTI (AbuseIPDB, AlienVault OTX) and GeoIP; severity escalates automatically on high-confidence threats. Optional **LLM triage** (Claude) produces a verdict + summary per alert.
- **Respond (SOAR)** — a **progressive ban** engine: repeat offenders escalate down a configurable duration ladder (e.g. `10m → 30m → 1h → 24h → permanent`), all editable from the UI. Supports **automatic banning** (no manual approval), an **observation window**, an **IP whitelist** (trusted IPs are never banned), per-offender **dedup** (one open action per IP), and a **per-IP response view** with bulk dismiss. Enforcement via nftables (agent-side), MikroTik, or CrowdSec LAPI.
- **Visualize** — a customizable, drag-and-drop dashboard (stats, severity, top IPs/rules, MITRE, attack-origin map, gap-filled timeline) with a precise **calendar + time range picker**, plus automated reports.
- **Operate** — RBAC with granular permissions, TOTP 2FA, append-only audit log, ticketing (Tier-2 escalation), notifications (Telegram / email / webhook), and full **i18n**.

### Roadmap

| Phase | Scope | Status |
|---|---|---|
| **Phase 1** | Linux agent, mTLS ingest, gateway + normalization, NATS, Postgres+TimescaleDB, Sigma detection + auto MITRE labeling, API + RBAC + audit log, base Web UI | ✅ |
| **Phase 2** | Windows/macOS agent, CTI enrichment (AbuseIPDB/OTX/GeoIP), response engine (nftables/Mikrotik/CrowdSec LAPI), TOTP 2FA, notifications (Telegram/email/webhook) | ✅ |
| **Phase 3** | LLM worker (Claude/heuristic), automated reports, community blocklist | ✅ |
| **Phase 4** | Admin/UX polish, full i18n, UI-managed detection rules, configurable progressive-ban (auto-ban + IP whitelist + dedup), per-IP response view, dashboard time-range picker + searchable events/alerts | ✅ |
| **Phase 5** | FIM + file-hash reputation (CIRCL/VirusTotal), endpoint file quarantine/delete on known-bad hash, agent self-uninstall on revoke, open-source/self-hosted LLM (Ollama), AI report summary (on-demand + scheduled) | ✅ |
| Phase 6 | Windows/macOS detection rules, Android agent, rule/integration marketplace, Helm chart | planned |

### Detection coverage by platform

The detection pipeline (log parsing → Sigma rules → enrichment → progressive ban) is
**verified end-to-end on Linux**. Other platforms collect and ship logs, but their event
parsing + detection rules are still in progress.

| Platform | Log collection | Detection (parse + rules) | End-to-end verified |
|---|---|---|---|
| **Linux** (sshd / journald) | ✅ | ✅ SSH brute force, invalid user, root login, sudo, FIM + malicious-hash | ✅ tested |
| **Windows** (Event Log: Security/System) | ✅ ships events | 🚧 4625/RDP-SMB brute-force parsing + rules WIP | ❌ not yet tested |
| **macOS** | ✅ ships logs | 🚧 rules WIP | ❌ not yet tested |

> So far DeusWatch's detection & response have been validated on Linux. Windows agents
> already stream their Event Log to the manager (ingest works), but Windows-specific
> normalization and Sigma rules are not finished — treat Windows/macOS detection as
> experimental until marked verified here.

## Architecture

```
Agent (Go) ──mTLS──> Ingest Gateway ──> NATS JetStream ──> Worker (detect/enrich/respond/llm)
                                                                  │
                                          PostgreSQL 16 + TimescaleDB
                                                                  │
                                              API Server (Go) ──> Web UI (React + Vite)
```

Full design details: see [DeusWatch.md](DeusWatch.md).

## Integrations

Connectors are added and configured from the **Integrations** menu in the UI (secrets are
encrypted at rest and write-only). Currently available:

| Type | Integration | What it does |
|---|---|---|
| 🛡️ Firewall | **nftables (agent-side)** | Endpoint auto-block: the agent adds the active blocklist to a local nftables set and drops matching traffic. |
| 🛡️ Firewall | **MikroTik RouterOS** | Pushes blocked IPs to a RouterOS address-list via the REST API. |
| 🛡️ Bouncer | **CrowdSec LAPI** | Creates/removes ban decisions via `cscli` so CrowdSec bouncers enforce them. |
| 🔎 CTI | **AbuseIPDB** | Enriches source IPs with an abuse-confidence score. |
| 🔎 CTI | **AlienVault OTX** | Enriches source IPs with threat-intel pulse counts. |
| 🔔 Notify | **Telegram · Email (SMTP) · Webhook** | Real-time alerts with dedup/throttle (configured via env). |
| 🤖 LLM | **Anthropic Claude** | Per-alert triage: verdict + summary (heuristic fallback when no key). |

Threat-intel also includes **GeoIP** (attack-origin map) and an opt-in **community blocklist**.

## Quick start

One command brings up the whole stack (db, NATS, cert generation, API, gateway, worker, web UI):

```bash
git clone https://github.com/FirdausYudha/DeusWatch.git
cd DeusWatch
docker compose -f deploy/docker-compose.yml up -d --build
```

- **Web UI:** http://localhost:5173 · **API:** http://localhost:8080
- **Default login:** `admin` / `thewatcher` (change via `ADMIN_PASSWORD`, or in **Users**/**Settings** after first login)
- Self-registration is **disabled by default** (admins create users in the UI); set `REGISTRATION_ENABLED=1` to allow viewer-role sign-ups from the login page.

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

## Documentation

| Doc | Purpose |
|---|---|
| [DeusWatch.md](DeusWatch.md) | Full architecture & design reference |
| [SECURITY.md](SECURITY.md) | Threat model & responsible-disclosure policy |
| [LICENSE](LICENSE) | AGPL-3.0 |
| In-app **Settings → docs** | Operator guidance, surfaced in the UI |

The fastest way to learn DeusWatch is to run the Quick start, log in, and trigger an SSH
brute force against a monitored host — you'll watch it flow from alert → enrichment → MITRE
label → progressive-ban recommendation in real time.

## Tech stack

Go · PostgreSQL + TimescaleDB · NATS JetStream · Sigma · React + Vite + Tailwind ·
Docker · LLM provider via the official Anthropic SDK (Claude).

## Security

A security system that isn't secure is an irony. mTLS is required, RBAC from day one,
encrypted secrets, append-only audit log. See [SECURITY.md](SECURITY.md) for the
responsible-disclosure policy.

## License

[AGPL-3.0](LICENSE) — free to self-host forever, anti vendor lock-in.

## Support

DeusWatch is built and maintained in the open, for free. If it's useful to you, a small
donation keeps the lights on and is hugely appreciated — thank you! 🙏

[![Saweria](https://img.shields.io/badge/Saweria-donate-FF5E5B.svg)](https://saweria.co/DeusLoVult1) — 🇮🇩 Indonesia (QRIS / GoPay / OVO / DANA)

[![Ko-fi](https://img.shields.io/badge/Ko--fi-support-FF5E5B.svg)](https://ko-fi.com/deuslovult1) — 🌏 International (PayPal / card)

You can also use the **Sponsor ♥** button at the top of this repo, or the **♥ Support DeusWatch**
link inside the app.
