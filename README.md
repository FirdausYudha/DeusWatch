<div align="center">

# DEUSWATCH

**All-in-One, Open Source, Self-Hosted Security Platform.**

SIEM · IDS/IPS · lightweight SOAR · CTI enrichment · LLM-based analysis - in one lightweight, modular system.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Phase%201--5%20complete%20·%20detection%20Linux--tested-green.svg)]()
[![Made with Go](https://img.shields.io/badge/Go-backend-00ADD8.svg)]()
[![Web: React + Vite](https://img.shields.io/badge/Web-React%20%2B%20Vite-61DAFB.svg)]()

[Features](#features) · [Integrations](#integrations) · [Quick start](#quick-start) · [Documentation](#documentation) · [Support ♥](#support)

</div>

---

> ⚠️ **Status: active development.** Phases 1-5 are implemented (ingest, detection, enrichment,
> response, FIM + hash reputation, endpoint remediation, AI reports). Detection & response are
> verified end-to-end on Linux; Windows detection is still in progress. Functional for labs
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

- **Ingest** - lightweight Go agents ship logs over mTLS (Linux/Windows); a gateway normalizes them into a common event schema on NATS JetStream.
- **Detect** - [Sigma](https://github.com/SigmaHQ/sigma) rules, both single-event and aggregation/correlation (e.g. SSH brute force = N failures from one IP; **port scan** = many firewall drops from one IP; Windows logon brute force). Coverage spans **SSH/auth + sudo privesc**, **web attacks** (SQLi, path traversal, LFI/RFI, scanner UAs, Shellshock, webshell), **FIM** (incl. webshell-in-uploads → containment), and **Windows** (process/PowerShell LOLBins, account/group changes, audit-log-cleared). Rules are **DB-backed and fully managed from the UI** (Wazuh-style): browse, edit, toggle, add or delete - built-ins are seeded on first start, custom rules validated on save. Alerts are auto-labeled with **MITRE ATT&CK** technique/tactic.
- **Extend** - support **new log sources without code** via **[custom decoders](docs/features/11-decoders.md)** (data-driven regex → fields, live-reloaded, with an in-UI tester on your own raw lines), and ingest **Suricata / Emerging Threats (ET Open/Pro)** network-IDS alerts as a first-class source (see [docs/suricata.md](docs/suricata.md)).
- **Enrich** - source IPs scored with CTI (AbuseIPDB, AlienVault OTX) and GeoIP; **country resolved from AbuseIPDB → OTX → GeoIP** and severity escalates automatically on high-confidence threats. Lookups are cached with a **UI-configurable dedup window** so an IP isn't re-queried (sparing API quota); no key configured shows an honest "-", never fabricated data. Optional **LLM analysis** (provider-agnostic: Claude, Ollama, or any OpenAI-compatible endpoint) powers AI report summaries (on-demand + scheduled), with opt-in per-alert triage.
- **Respond (SOAR)** - a **progressive ban** engine: repeat offenders escalate down a configurable duration ladder (e.g. `10m → 30m → 1h → 24h → permanent`), all editable from the UI. Supports **automatic banning** (no manual approval), an **observation window**, an **IP whitelist** (trusted IPs are never banned), per-offender **dedup** (one open action per IP), a **per-IP response view**, **free-text search**, **bulk select/approve/dismiss**, and **unban** to lift an active block on the enforcer. Enforcement via nftables (agent-side), MikroTik, or CrowdSec LAPI. Beyond IP bans, **[network containment](docs/features/10-network-containment.md)** isolates a *compromised host* from the LAN (host self-isolation + edge block) when a rule authorizes it, and a **trusted-session gate** suppresses file-change alerts that correlate with a login from a whitelisted admin/deploy IP (an official change, not an attack).
- **Visualize** - a customizable, drag-and-drop dashboard (stats, severity, top IPs/rules, MITRE, attack-origin map, gap-filled timeline) with a precise **calendar + time range picker**, a **log-storage health panel** (DB size/budget, retention lifecycle, replication status), plus automated reports.
- **Operate** - RBAC with granular permissions, TOTP 2FA, append-only audit log, ticketing (Tier-2 escalation), notifications (Telegram / email / webhook with a UI-configurable severity threshold + scheduled report delivery), JSON **webhook export** to external tools, **config profile import/export** to clone one server's setup onto another, an in-app **update check**, and full **i18n**.

### Roadmap

| Phase | Scope | Status |
|---|---|---|
| **Phase 1** | Linux agent, mTLS ingest, gateway + normalization, NATS, Postgres+TimescaleDB, Sigma detection + auto MITRE labeling, API + RBAC + audit log, base Web UI | ✅ |
| **Phase 2** | Windows agent, CTI enrichment (AbuseIPDB/OTX/GeoIP), response engine (nftables/Mikrotik/CrowdSec LAPI), TOTP 2FA, notifications (Telegram/email/webhook) | ✅ |
| **Phase 3** | LLM worker (Claude/heuristic), automated reports, community blocklist | ✅ |
| **Phase 4** | Admin/UX polish, full i18n, UI-managed detection rules, configurable progressive-ban (auto-ban + IP whitelist + dedup), per-IP response view, dashboard time-range picker + searchable events/alerts | ✅ |
| **Phase 5** | FIM + file-hash reputation (CIRCL/VirusTotal), endpoint file quarantine/delete on known-bad hash, agent self-uninstall on revoke, open-source/self-hosted LLM (Ollama), AI report summary (on-demand + scheduled), **JSON webhook export, config-profile import/export, UI alert threshold + scheduled report delivery to Telegram/email** | ✅ |
| **Phase 6** | **Windows detection rules** (process/PowerShell/account/audit), **web-attack + sudo rule sets**, **network containment + trusted-session gate**, **Suricata/ET network-IDS ingestion**, **custom decoders** (data-driven log sources, UI editor + tester), agent name across Events/Response/Report + full-JSON log view | ✅ |
| Phase 7 | Linux process audit (auditd/sysmon), rule/integration marketplace, Helm chart | planned |

### Detection coverage by platform

The detection pipeline (log parsing → Sigma rules → enrichment → progressive ban) is
**verified end-to-end on Linux**. Other platforms collect and ship logs, but their event
parsing + detection rules are still in progress.

| Platform | Log collection | Detection (parse + rules) | End-to-end verified |
|---|---|---|---|
| **Linux** (sshd / journald / firewall / web / FIM) | ✅ | ✅ SSH brute force + break-in/scan/root-refused, **sudo/su privesc**, **web attacks** (SQLi, traversal, LFI/RFI, scanner UAs, Shellshock, webshell), FIM + malicious-hash + **webshell-in-uploads → containment**, **port scan** (firewall drops) | ✅ tested |
| **Windows** (Event Log: Security/System) | ✅ ships events | ✅ 4625 brute force + 4740 lockout; **4688/4104 process & PowerShell (suspicious PowerShell, LOLBin exec)**, account/group changes (4720/4728/4732), **1102 audit-log-cleared** - EventID normalizer + Sigma rules | 🟡 server pipeline verified; real-agent log read pending |
| **Network** (Suricata / Emerging Threats) | ✅ via a Suricata sensor's `eve.json` | ✅ every ET/Suricata alert ingested as a first-class event (bans/containment apply) | 🟡 needs a Suricata sensor - see [docs/suricata.md](docs/suricata.md) |
| **Any other source** | via a **[custom decoder](docs/features/11-decoders.md)** (regex → fields, no code) | write rules scoped to the decoder's category | operator-defined |

> Linux detection & response are validated end-to-end. **Windows** maps logon events by
> numeric EventID (4625 failed, 4624 success, 4740 lockout) - language independent - with a
> brute-force aggregation rule + a lockout rule. The **server-side detection pipeline is
> verified end-to-end**: a batch of 4625 events sent over the real mTLS agent protocol is
> normalized (user/IP/os), and the aggregation produces a *Windows Logon Brute Force*
> (T1110.001) alert. The one piece not yet verified on real hardware is the **agent reading a
> live Windows Security log** (the PowerShell/XML collection); treat that as **beta**.

> **Port-scan detection** needs a firewall log source. Linux agents tail `/var/log/ufw.log`
> by default (dataset `firewall`) - enable firewall logging on the host (`ufw logging on`, or
> add an `iptables/nftables` `LOG` rule). Many drops from one source IP within a minute raise a
> *Port Scan / Network Probe* (T1046) alert.

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
| 🔔 Notify | **Telegram · Email (SMTP) · Webhook** | Real-time alerts (severity threshold set in the UI) + **scheduled report delivery**. Channel credentials via env - see [docs/notifications.md](docs/notifications.md). |
| 📤 Export | **Webhook (JSON)** | One-click POST of events/alerts or a report to an external tool (SIEM, n8n, Zapier, custom). |
| 🤖 LLM | **Claude · Ollama · OpenAI-compatible** | AI report summaries (on-demand + scheduled); optional opt-in per-alert triage. Provider-agnostic; runs free & offline via Ollama. |

Threat-intel also includes **GeoIP** (attack-origin map) and an opt-in **community blocklist**.

## Quick start

One command brings up the whole stack (db, NATS, cert generation, API, gateway, worker, web UI):

```bash
git clone https://github.com/FirdausYudha/DeusWatch.git
cd DeusWatch
docker compose -f deploy/docker-compose.yml up -d --build
```

- **Web UI:** http://localhost:9173 · **API:** http://localhost:9080
- **Default login:** `admin` / `thewatcher` (change via `ADMIN_PASSWORD`, or in **Users**/**Settings** after first login)
- Self-registration is **disabled by default** (admins create users in the UI); set `REGISTRATION_ENABLED=1` to allow viewer-role sign-ups from the login page.

### Custom ports

The host-published ports avoid the common `8080`/`5173` collisions and are all overridable in
`deploy/.env` (the container ports never change, so nothing else needs touching):

| Service | Env var | Default |
|---|---|---|
| Web UI | `DEUSWATCH_WEB_PORT` | `9173` |
| API / agent enroll & install | `DEUSWATCH_API_PORT` | `9080` |
| Gateway (mTLS ingest) | `DEUSWATCH_GATEWAY_PORT` | `9443` |
| PostgreSQL | `DEUSWATCH_DB_PORT` | `5432` |

**How to change a port:**

1. Create/edit `deploy/.env` (copy `deploy/.env.example` if you don't have one):
   ```dotenv
   DEUSWATCH_WEB_PORT=15173
   DEUSWATCH_API_PORT=15080
   DEUSWATCH_GATEWAY_PORT=15443
   ```
2. Re-up the stack with that env file:
   ```bash
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
   ```
3. Open the UI at the new web port (e.g. `http://localhost:15173`). The **Add agent** wizard
   reads the API/gateway ports automatically (via `GET /api/agent/install-info`), so the
   generated install one-liner always targets the right ports - nothing else to edit.

> Only the **host-published** port changes; the container still listens on `8080`/`8443`/`80`
> internally, so the app config is untouched. If you change the gateway port **after** agents
> are already enrolled, update their `GATEWAY_URL` (or re-run the install command) to match.

### Updating an existing deployment

Pull the latest code and rebuild in one step (DB migrations auto-apply on API start; your
`deploy/.env` and local data are gitignored, so they survive):

```bash
./scripts/update.sh         # Linux/macOS host   (.\scripts\update.ps1 on Windows)
```

Or manually:

```bash
git pull --ff-only
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
```

**Check for updates** from the UI: **Settings → Software updates → Check for update** compares
your running build against the latest commit on GitHub (read-only). The update itself runs on
the host with `./scripts/update.sh` - the web app never controls Docker, by design.

**Auto-update (optional)** with a host cron (runs at the host level, not from the container):

```bash
# daily at 04:00 - pull + rebuild if there's anything new
0 4 * * *  cd /path/to/DeusWatch && ./scripts/update.sh >> /var/log/deuswatch-update.log 2>&1
```

## Deploying agents

In the UI go to **Agents → + Add agent**, pick the OS (Linux / Windows), set **Manager host** to
the address agents will reach (the LAN IP for cross-host, e.g. `192.168.1.10:9080`), and copy
the generated one-liner. It downloads the agent, enrols with a one-time token, installs an
auto-start service, and connects - e.g. on Linux (ports auto-filled from your config):

```bash
curl -fsSL http://<manager>:9080/api/agent/install.sh | sudo MANAGER=<manager> TOKEN=<token> NAME=<name> API_PORT=9080 GW_PORT=9443 sh
```

The manager must allow inbound on the API port **9080** (enrol/install) and gateway port
**9443** (mTLS) - substitute your own values if you changed `DEUSWATCH_API_PORT` /
`DEUSWATCH_GATEWAY_PORT`:

- Linux manager: `sudo ufw allow 9080,9443/tcp` (if `ufw` is active)
- Windows manager: `New-NetFirewallRule -DisplayName "DeusWatch" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9080,9443`

Agents authenticate the manager by the deployment's **private CA**, not by hostname/IP, so
cross-host deployments work without per-IP certificate tweaks. To additionally pin the
manager's IP into the server certificate SAN (optional), set `MANAGER_IP` in `deploy/.env`
before first start (e.g. `MANAGER_IP=192.168.1.10`); changing it later means regenerating
certs (delete `deploy/certs/*` or run certgen with `-force`) and re-enrolling agents (a new
CA invalidates old certs).

### Troubleshooting an offline agent

Online status is driven by the heartbeat to the gateway (`:9443` by default). If an agent shows
**offline** while `systemctl status deuswatch-agent` looks healthy, check its logs:

```bash
sudo journalctl -u deuswatch-agent -n 30 --no-pager
```

- `connection refused` / timeout → the manager's firewall is blocking the gateway port (9443), or the wrong `MANAGER`/host.
- `x509: certificate signed by unknown authority` → the agent enrolled against a different CA; re-enrol after regenerating certs.

## Notifications (Telegram & email)

DeusWatch can push **alerts** (above a severity you pick in the UI) and **scheduled reports** to
**Telegram** and **email**. Channel credentials live in env (they're secrets); the severity
threshold and delivery schedule are set in the UI. Quick Telegram setup:

1. **Create a bot** - message [@BotFather](https://t.me/BotFather), send `/newbot`, copy the **token**.
2. **Get your chat id** - DM the bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and read
   `"chat":{"id":...}` (or message [@userinfobot](https://t.me/userinfobot)). A group id is negative.
3. **Set it in `deploy/.env`:**
   ```dotenv
   TELEGRAM_BOT_TOKEN=123456789:AAE...
   TELEGRAM_CHAT_ID=123456789
   ```
4. **Restart the worker:** `docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d worker`
5. **Turn it on:** **Settings → Alert notifications** (severity threshold) and **Report → Scheduled delivery** (cadence).

Full guide incl. email/SMTP (Gmail App Password) and webhook export: **[docs/notifications.md](docs/notifications.md)**.

## Documentation

| Doc | Purpose |
|---|---|
| [DeusWatch.md](DeusWatch.md) | Full architecture & design reference |
| [docs/features/](docs/features/) | **Per-menu modules** (11) - how each feature works, how to use it, ports, tech, variables |
| [docs/new-log-source.md](docs/new-log-source.md) | **Tutorial**: add a new log source end-to-end (decoder → test → rule → ban) |
| [docs/notifications.md](docs/notifications.md) | Connect Telegram / email + scheduled report delivery |
| [docs/llm-providers.md](docs/llm-providers.md) | AI providers (Ollama / OpenAI / Gemini / Groq / Claude) + triage-vs-report selector |
| [docs/llm-ollama.md](docs/llm-ollama.md) | Connect a local LLM (Ollama) for AI summaries + troubleshooting |
| [docs/suricata.md](docs/suricata.md) | Suricata / Emerging Threats (ET Open/Pro) network-IDS integration |
| [docs/blocklist-feed.md](docs/blocklist-feed.md) | Sync bans to external firewalls (Palo Alto EDL, OPNsense, pfSense, MikroTik) |
| [decoders/](decoders/README.md) | Custom decoders: data-driven log parsing for new sources |
| [docs/storage.md](docs/storage.md) | Log storage: retention/lifecycle, remote DB (Server B), replication, near-full alerts |
| [SECURITY.md](SECURITY.md) | Threat model & responsible-disclosure policy |
| [LICENSE](LICENSE) | AGPL-3.0 |

The fastest way to learn DeusWatch is to run the Quick start, log in, and trigger an SSH
brute force against a monitored host - you'll watch it flow from alert → enrichment → MITRE
label → progressive-ban recommendation in real time.

## Tech stack

Go · PostgreSQL + TimescaleDB · NATS JetStream · Sigma · React + Vite + Tailwind ·
Docker · provider-agnostic LLM (official Anthropic SDK for Claude; OpenAI-compatible API for Ollama & others).

## Security

A security system that isn't secure is an irony. mTLS is required, RBAC from day one,
encrypted secrets, append-only audit log. See [SECURITY.md](SECURITY.md) for the
responsible-disclosure policy.

## License

[AGPL-3.0](LICENSE) - free to self-host forever, anti vendor lock-in.

## Support

DeusWatch is built and maintained in the open, for free. If it's useful to you, a small
donation keeps the lights on and is hugely appreciated - thank you! 🙏

[![Saweria](https://img.shields.io/badge/Saweria-donate-FF5E5B.svg)](https://saweria.co/DeusLoVult1) - 🇮🇩 Indonesia (QRIS / GoPay / OVO / DANA)

[![Ko-fi](https://img.shields.io/badge/Ko--fi-support-FF5E5B.svg)](https://ko-fi.com/firdausyudha) - 🌏 International (PayPal / card)

You can also use the **Sponsor ♥** button at the top of this repo, or the **♥ Support DeusWatch**
link inside the app.
