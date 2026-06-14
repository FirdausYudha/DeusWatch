# DeusWatch — Design Document
## All-in-One Open Source Security Platform

> This document is the blueprint to bring into Claude Code. Version 1.0 — all design decisions are final.
> Official name: **DeusWatch**. Schema: **DCS (DeusWatch Core Schema)**. License: **AGPL-3.0**.

---

## 1. Vision

An open-source security detection and response platform that combines SIEM, IDS/IPS, lightweight SOAR, CTI enrichment, and LLM-based analysis capabilities in a single system that is lightweight, modular, and fully self-hosted. Target users range from beginners (noob-friendly defaults) to SOC professionals (fully customizable), with all components running in Docker and easy to migrate.

Core principle: **don't reinvent the wheel**. We leverage standards and ecosystems that are already mature (Sigma rules, the CrowdSec bouncer protocol, PostgreSQL, NATS) and focus on building the integration layer and the user experience no vendor offers in a single package.

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          ENDPOINTS                              │
│   Agent (Go, single binary) — Linux / Windows / macOS          │
│   Sends: raw logs, FIM events, system metrics                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │ mTLS (mandatory, no plaintext option)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    INGEST GATEWAY (Go)                          │
│   Agent authentication, rate limiting, schema validation,       │
│   log normalization to the internal format (ECS-like)           │
└──────────────────────────┬──────────────────────────────────────┘
                           │ publish
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              NATS JetStream (message bus + persistence)         │
│   Streams: logs.raw → logs.normalized → logs.enriched → alerts │
│   No cache, no cache collisions. Pure streaming.                │
└───────┬──────────────┬───────────────┬──────────────┬───────────┘
        ▼              ▼               ▼              ▼
┌──────────────┐ ┌─────────────┐ ┌────────────┐ ┌──────────────┐
│  DETECTION   │ │ ENRICHMENT  │ │  RESPONSE  │ │  LLM WORKER  │
│  ENGINE      │ │ WORKER      │ │  ENGINE    │ │              │
│  Sigma rules │ │ CTI lookup: │ │ Bouncer:   │ │ Mode:        │
│  + auto-     │ │ AbuseIPDB,  │ │ Mikrotik,  │ │ per-log /    │
│  labelling   │ │ OTX, GeoIP  │ │ nftables,  │ │ per-enriched │
│  (MITRE tag) │ │ + TTL cache │ │ CrowdSec   │ │ / daily      │
│              │ │ in Postgres │ │ LAPI compat│ │ batch        │
└──────┬───────┘ └──────┬──────┘ └─────┬──────┘ └──────┬───────┘
       └────────────────┴──────────────┴───────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│   PostgreSQL 16 + TimescaleDB (log time-series, compression,    │
│   retention policy) + pgvector (embeddings for RAG/LLM)         │
│   Replication: streaming replication / Patroni for HA           │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│   API SERVER (Go) ── REST + WebSocket, RBAC, audit log          │
│   WEB UI (React + Vite) ── customizable dashboard (grid          │
│   drag-and-drop), dark mode, modern, real-time via WebSocket    │
└─────────────────────────────────────────────────────────────────┘
```

Each box is a single Docker container. Everything is orchestrated via one `docker-compose.yml` (noob-friendly mode) with a Helm chart option for Kubernetes in the future (pro mode).

---

## 3. Technology Decisions and Rationale

| Component | Choice | Rationale |
|---|---|---|
| Core language & agent | Go | Single binary, lightweight, cross-compile Linux/Windows/macOS, good concurrency for ingest |
| Message bus | NATS JetStream | Built-in persistence, far lighter than Kafka, not a cache so there are no cache-collision issues like in Shuffle |
| Log database | PostgreSQL + TimescaleDB | Native time-series, columnar compression, automatic retention, mature replication |
| Vector / RAG | pgvector (Postgres extension) | The LLM can semantic-search historical logs without a separate database |
| Detection rules | Sigma | Thousands of community rules, free MITRE ATT&CK tags = auto-labelling (brute force, password guessing, etc.) |
| Bouncer/IPS | CrowdSec LAPI protocol implementation | Compatible with all existing CrowdSec bouncers + can subscribe to the CrowdSec community blocklist |
| Frontend | React + Vite + Tailwind | Modern, fast, broad component ecosystem |
| LLM | Provider-agnostic | Ollama (local/privacy), OpenAI-compatible API, Anthropic API — the user chooses |

A key decision about the **enrichment cache** (a lesson from Shuffle): CTI lookup results are stored as **rows in Postgres with a TTL column**, not in an in-memory cache. The worker checks the table before calling an external API. Deterministic, queryable, never "collides" — if two workers look up the same IP at the same time, a unique constraint in the database resolves it, not cache logic.

---

## 4. Security-by-Design (Non-Negotiable)

An insecure security system is an irony. The rules below apply from the first commit and must not be broken for the sake of development convenience.

**Agent–server communication.** All agent communication uses mTLS. There is no plaintext mode, not even for development (use self-signed certificates auto-generated by the installer). Agent enrollment uses single-use tokens with a short lifetime; after enrolling, the agent receives a unique client certificate that can be revoked individually from the UI.

**Authentication and authorization.** RBAC from day one with three built-in roles: **Viewer** (only views the dashboard and alerts — pure read-only, suitable for management/monitoring screens), **Analyst** (reads everything, investigates, acknowledges alerts, and approves remediation recommendations — but cannot edit rules, settings, or users; this is the "discovery" role that can dig in without being able to break anything), and **Admin** (full read-write-execute: manage rules, users, integrations, retention, and execute blocking). Pro mode adds a **custom role builder**: an admin can assemble their own role from granular permissions (e.g. a special role allowed to manage rules but not users). Passwords are hashed with Argon2id. TOTP 2FA support in the MVP, not "later". Sessions use rotating tokens, not long-lived JWTs. Every state-changing action (block IP, change rule, delete data) is recorded in an append-only audit log along with the actor's role identity.

**Secrets.** CTI API keys, Mikrotik credentials, and LLM API keys are stored encrypted in the database with envelope encryption (master key from an environment variable or file, with Vault integration documented for pro mode). Secrets never appear in application logs and are masked in the UI.

**Supply chain.** The agent binary and Docker images are signed (cosign). CI runs `govulncheck`, `gosec`, and dependency scanning on every PR. An SBOM is generated for each release. Because this is open source on GitHub, include a SECURITY.md with a responsible-disclosure policy.

**Input handling.** All incoming logs are treated as dangerous data: schema validation at the gateway, parameterized queries without exception, sanitization before rendering in the UI (log injection into the dashboard is a real attack vector against SOC analysts). Specifically for the LLM feature: logs sent to the LLM may contain attacker prompt injection — the LLM output is **never** executed automatically as a blocking action; the LLM only provides recommendations that a human must confirm, unless the user explicitly enables auto-mode with a configurable confidence level.

**Safe autoblocking.** The response engine has mandatory safeguards: an allowlist (admin IPs are never blocked), dry-run mode by default on first install, a TTL on every block (no permanent block without confirmation), and one-click rollback. The aggressiveness level can be set per detection source (requirement point 19).

---

## 5. Repo Structure (Monorepo)

```
deuswatch/
├── cmd/
│   ├── agent/            # agent entrypoint (single binary)
│   ├── gateway/          # ingest gateway
│   ├── api/              # API server
│   └── worker/           # detection, enrichment, response, llm
│                         # (one binary, mode selected via flag)
├── internal/
│   ├── agent/            # per-OS log collectors, FIM (fsnotify + hashing)
│   ├── ingest/           # normalization, internal schema (ECS-like)
│   ├── detect/           # Sigma engine, MITRE auto-labelling
│   ├── enrich/           # AbuseIPDB, OTX, GeoIP clients + TTL store
│   ├── respond/          # Mikrotik API, nftables, CrowdSec LAPI drivers
│   ├── llm/              # provider abstraction, RAG via pgvector
│   ├── store/            # Postgres/Timescale, migrations, repository
│   ├── auth/             # RBAC, Argon2id, TOTP, audit log
│   └── bus/              # NATS JetStream abstraction
├── web/                  # React + Vite + Tailwind
│   ├── src/
│   │   ├── dashboard/    # customizable grid (drag-drop widgets)
│   │   ├── alerts/
│   │   ├── agents/
│   │   ├── rules/        # Sigma editor + blocklist manager
│   │   └── settings/
├── deploy/
│   ├── docker-compose.yml          # noob mode: one command to run
│   ├── docker-compose.prod.yml    # pro mode: replication, resource limits
│   └── certs/                      # automatic mTLS generation script
├── .github/
│   └── FUNDING.yml       # Saweria + Ko-fi → automatic Sponsor button
├── rules/                # default Sigma rules bundle + custom rules
├── migrations/           # SQL migrations (golang-migrate)
├── docs/
├── SECURITY.md
├── LICENSE               # AGPL-3.0 (DECIDED) — anti vendor-lock,
│                         #  opens a path to a hosted-version business model
└── README.md
```

---

## 6. MVP Phase 1 Spec (target: usable by other people)

The Phase 1 scope is deliberately small so it gets finished. Definition of done: someone can `docker compose up`, install the agent with a single curl command, and within five minutes see their server's logs arrive in the dashboard with an SSH brute-force alert detected automatically.

**Included in Phase 1:** Linux agent (log file + journald + basic FIM), mTLS enrollment, gateway + normalization, NATS JetStream, Postgres + TimescaleDB, a detection engine with a subset of Sigma rules (focus: SSH brute force, common web attacks, auth anomalies) plus auto-labelling from MITRE tags, an API server with RBAC + audit log, and a Web UI with a live log stream, an alerts page, agent management, and a simple grid dashboard (3–4 widget types: time-series, counter, top-N table, pie).

**Explicitly NOT in Phase 1:** Windows/macOS agent (Phase 2), CTI enrichment (Phase 2 — but the database schema already prepares its columns), autoblocking (Phase 2), LLM (Phase 3), ML anomaly detection (Phase 3), community blocklist sharing (Phase 3), report generator (Phase 3).

**Roadmap at a glance.** Phase 2: Windows + macOS agents, AbuseIPDB/OTX enrichment with a TTL store, response engine (Mikrotik + nftables + CrowdSec LAPI compat) with dry-run and aggressiveness levels, TOTP 2FA. Phase 3: LLM worker (three trigger modes), RAG via pgvector, daily/monthly/yearly reports powered by LLM, community blocklist publish/subscribe, ML anomaly baseline. Phase 4: Android agent, rule/integration marketplace, Helm chart.

---

## 7. DCS — DeusWatch Core Schema (DECIDED)

Decision: **an ECS-named subset**. All core fields follow the official Elastic Common Schema names and structure so community Sigma rules are directly compatible; fields with no ECS counterpart go into the custom `deuswatch.*` namespace. This schema is designed for three main consumers: dashboard aggregation, CTI enrichment, and context for the LLM.

**Core field groups (ECS-compliant):**

| Group | Main fields | Purpose |
|---|---|---|
| Event | `@timestamp`, `event.category`, `event.action`, `event.outcome`, `event.severity`, `event.dataset`, `event.original` | Basis of all dashboard aggregations (time-series, severity breakdown) |
| Source/Dest | `source.ip`, `source.port`, `source.geo.country_iso_code`, `source.geo.city_name`, `destination.ip`, `destination.port` | Top-N attacker IPs, geographic map, the main enrichment key |
| Host & Agent | `host.name`, `host.os.type`, `host.ip`, `agent.id`, `agent.version` | Per-endpoint filtering, agent management |
| User | `user.name`, `user.domain` | Per-account brute force detection, password guessing |
| Network | `network.protocol`, `network.transport` | Protocol breakdown |
| File (FIM) | `file.path`, `file.hash.sha256`, `file.owner`, `file.mode` | File Integrity Monitoring |
| Process | `process.name`, `process.pid`, `process.command_line` | Endpoint context (Phase 2+) |
| Detection | `rule.id`, `rule.name`, `threat.technique.id`, `threat.technique.name`, `threat.tactic.name` | MITRE ATT&CK auto-labelling from Sigma tags |
| CTI enrichment | `threat.indicator.ip`, `threat.indicator.confidence`, `threat.feed.name`, `threat.indicator.last_seen` | AbuseIPDB/OTX lookup results — ECS already has an official `threat.*` fieldset for this |

**Custom `deuswatch.*` namespace** (for what ECS doesn't have):

| Field | Contents |
|---|---|
| `deuswatch.enrichment.status` | `pending` / `enriched` / `failed` / `skipped` — per-log pipeline status |
| `deuswatch.enrichment.abuse_confidence` | A 0–100 score from AbuseIPDB (used by the dashboard and the autoblocking threshold) |
| `deuswatch.enrichment.otx_pulse_count` | Number of OTX pulses containing that IP |
| `deuswatch.label` | Auto-labelling result: `bruteforce`, `password_guessing`, `mailscam`, etc. |
| `deuswatch.llm.verdict` | `benign` / `suspicious` / `malicious` / `needs_review` |
| `deuswatch.llm.summary` | LLM analysis summary (also embedded into pgvector for RAG) |
| `deuswatch.llm.analyzed_at` | Analysis timestamp, for the daily batch mode |

The data flow design: a log arrives with `deuswatch.enrichment.status = pending` → the enrichment worker fills the `threat.*` fieldset + score → the LLM worker reads **already-enriched** logs (per the trigger mode) and fills `deuswatch.llm.*`. The dashboard simply aggregates these fields without extra parsing — they are all indexed columns in TimescaleDB.

Schema discipline rule: new fields may only be added via a PR that changes the single schema definition file (`internal/ingest/schema.go` + SQL migration), no stray fields may appear out of nowhere in the code. This prevents the schema from rotting over time.

---

## 8. Log Storage & Retention

The log table is a **TimescaleDB hypertable with per-day chunks** — each day is a separate physical partition, so deleting old data is an instant chunk drop that does not load the database. Three retention mechanisms run on top of it, all configurable from the UI:

**Time-based retention policy, per data category.** Each category has its own age that can be set freely (7 days / 30 days / 90 days / 1 year / forever). Sensible defaults: raw logs 30 days (the largest volume, forensic value goes stale quickly), alerts + enriched logs 1 year, audit log 2 years. Implementation: TimescaleDB's built-in `add_retention_policy()`.

**Automatic compression.** Chunks older than 7 days (configurable) are compressed with TimescaleDB columnar compression — typical savings of 90%+, and compressed data is still queryable. This is what makes 1-year retention realistic on a small disk: a rough estimate, 500 GB/year of raw logs shrinks to ±50–70 GB.

**Disk-watermark-based janitor (safety net).** A lightweight service monitors the data volume's disk usage. When it crosses a watermark (default **90%**, configurable — deliberately not 98% because PostgreSQL running out of disk risks corruption and a total halt), the janitor drops the oldest chunks earlier than their retention schedule until usage falls to a safe level. Every janitor trigger produces a `high`-severity alert so the admin knows the disk needs growing or retention needs tightening.

**Cold archive (optional, Phase 3).** Before a chunk is dropped by retention or the janitor, it can be exported automatically to object storage (self-hosted MinIO / S3) as a compressed Parquet file — for compliance and long-term forensic needs without loading the main database.

All of these settings appear in the UI under Settings → Storage with a visual estimate of disk usage per category, so a noob user can simply use the defaults while a pro user can tune granularly.

---

## 9. Severity & Automatic Remediation Recommendations

**Severity model (5 levels):** `info` → `low` → `medium` → `high` → `critical`, stored in `event.severity` (numeric 0–4 for easy dashboard aggregation). The base severity source is the Sigma rule's built-in `level` field whose values match exactly, so no complex mapping is needed. On top of that, **dynamic escalation** by the enrichment worker applies: by default, any alert with `deuswatch.enrichment.abuse_confidence ≥ 90` goes up one level; an IP appearing in ≥ 5 OTX pulses goes up one level; all escalation rules can be customized from the UI. The escalated severity is stored separately from the original severity so it stays auditable.

**Remediation recommendations: a two-layer hybrid architecture.**

The first layer, **rule-based (primary)**: each detection label maps to a static recommendation playbook in a YAML file (`rules/playbooks/`). Example: the `bruteforce` label → recommendation "block source.ip with a 24-hour TTL, audit the target account, verify SSH rate-limiting". Deterministic, <1ms, no cost, fully auditable, and handles the majority of log volume. Playbooks can be added/edited by the user from the UI (fully customizable).

The second layer, **LLM (advisor)**: triggered only for cases the rule-based layer gives up on — `high`/`critical` severity without a matching playbook, new anomaly patterns, or multi-log correlation. The LLM receives the enriched log + historical context from pgvector (RAG) and produces a narrative recommendation. Per the security principle in section 4: LLM recommendations are **never executed automatically** — they always require human confirmation, because attacker-controlled log content is a prompt-injection vector.

Additional fields in the `deuswatch.*` namespace:

| Field | Contents |
|---|---|
| `deuswatch.severity.original` | The original severity from the Sigma rule |
| `deuswatch.severity.escalated_by` | The escalation rule that raised the level (audit trail) |
| `deuswatch.remediation.action` | Recommended action (from a playbook or the LLM) |
| `deuswatch.remediation.source` | `playbook` / `llm` |
| `deuswatch.remediation.status` | `recommended` / `approved` / `executed` / `dismissed` |

Relationship with the response engine (autoblocking): a playbook can mark a certain action as *auto-executable* (e.g. block IP for `bruteforce` with high confidence) per the user-configured aggressiveness level — whereas LLM-sourced recommendations are always manual-approve.

---

## 10. Response Engine: Multi-Target Banlist, Progressive Ban & Rule Management

**Driver architecture (Enforcer).** All blocking targets are abstracted behind a single Go interface: `Enforcer` with the contract `Block(ip, ttl, reason)`, `Unblock(ip)`, `Sync()`. Adding support for a new device = writing one driver, without touching the core logic. Driver roadmap:

| Phase | Driver |
|---|---|
| Phase 2 | nftables/iptables (local Linux via agent), Windows Firewall (via agent), Mikrotik (RouterOS API) |
| Phase 3 | CrowdSec LAPI (push decisions to the CrowdSec bouncer ecosystem), pfSense/OPNsense, generic webhook (for any device with an API) |
| Phase 4 | Cisco (ASA/IOS), Sophos XG, FortiGate |

A single IP can be blocked on many targets at once (e.g. Mikrotik at the edge + nftables on the server). The `bans` table in Postgres is the *source of truth* — drivers are just executors, and a periodic `Sync()` ensures the device state always matches the database (self-healing if a router is rebooted and loses its rules).

**Progressive ban (recidivism).** The ban duration increases automatically for repeat offenders. Default: the first violation **5 hours**; if the same IP performs suspicious activity again within the observation window (default 7 days), the duration is multiplied by an escalation factor (default 2×): 5 hours → 10 hours → 20 hours → 40 hours, up to a maximum cap (default 30 days). After N recidivist offenses (default 5), the system recommends a permanent ban — which still requires admin confirmation. All parameters (base duration, factor, window, cap, permanent threshold) can be set **per-label**: brute force can be aggressive, other labels can be more lenient. The per-IP ban history is stored in full for audit and shown on the IP detail page.

**Two-mode rule management (inspired by Wazuh, improved).** A **GUI builder** mode for beginners: a visual form to pick a DCS field → condition → threshold → severity, which behind the scenes produces standard Sigma YAML. A **text editor** mode for pros: write/paste Sigma YAML directly with real-time syntax validation. Because both produce the same format, a GUI-built rule can be opened in the text editor and vice versa. Two supporting features Wazuh lacks: **rule dry-run** (test a new rule against historical logs in the database before enabling it — immediately see how many alerts it would trigger, preventing noisy rules) and **rule versioning** (every change is saved like git history, one-click rollback if a new edit breaks something).

---

## 11. Multi-Channel Notifications & Alerting

All channels are abstracted behind a single `Notifier` interface (the same pattern as `Enforcer`), so adding a new channel = one new driver. Supported channels:

| Channel | Notes | Phase |
|---|---|---|
| Email (SMTP) | Universal, for alerts and PDF report delivery | 2 |
| Telegram | Official Bot API, free, real-time — the best channel for instant alerts | 2 |
| Generic webhook | Covers Slack, Discord, MS Teams, and any integration at once | 2 |
| ntfy / Gotify | Self-hosted push notifications, aligned with the project philosophy | 3 |
| WhatsApp | **Honest note:** the official API (WhatsApp Business/Cloud API) is paid per message and needs Meta approval; unofficial gateways (e.g. reverse-engineered libraries) are free but risk the number being blocked. Supported via a third-party gateway driver (Fonnte, etc.) with a clear disclaimer in the documentation | 3 |

**Smart routing, not a flood of notifications.** Each channel has its own routing rules set from the UI: severity threshold (e.g. Telegram only `high`/`critical`, email starting at `medium`), per-label filter, and quiet hours. Two mandatory anti-spam mechanisms: **deduplication** (identical alerts within a time window are merged into one message "brute force from 1.2.3.4 — 47 occurrences in 10 minutes", not 47 messages) and per-channel **throttling**. Alert fatigue is the number-one reason analysts ignore a SIEM — this design prevents it from the start.

**Reports through the same channels.** Daily/monthly/yearly reports (including the LLM-powered ones, part of the Phase 3 roadmap) are sent through the chosen channel: a short summary to Telegram, a full PDF to email.

---

## 12. Centralized Agent Management (Zero-Touch)

Principle: **never SSH/RDP into an agent to change anything**. This is a direct fix for the Wazuh pain (editing `ossec.conf` per machine).

**The separation of responsibilities that makes this easy.** Detection rules (Sigma) are evaluated entirely on the server — the agent never stores or executes a rule. Changing a rule applies instantly to all agents without any distribution. The only thing that lives on the agent is the **collection config**: the list of log sources (file paths, journald units, Windows Event channels), the list of FIM paths with their options (realtime/scheduled, hash algorithm, exclude patterns), and operational parameters (buffer size, bandwidth limit).

**Centralized config push.** The agent config is stored in Postgres as *desired state*, with three overriding layers: **global** → **group** → **per-agent override**. Agents are grouped via free-form tags (`os:linux`, `role:webserver`, `site:jakarta`) and a single agent can belong to many groups. A concrete example: add the FIM path `/etc/nginx/` to the `role:webserver` group from the UI → all web servers apply it, other machines are untouched.

**Distribution mechanism.** The agent maintains the same persistent mTLS connection as the log-shipping path — a new config is sent over that channel (instant push when online, pull on reconnect for an agent that was offline). Each config has a version number; the agent applies it **atomically** (validate first, apply, report back the active version), and if a new config makes the agent fail to run, the agent automatically rolls back to the last healthy version and reports the error — no agent dies from a config typo. The dashboard shows the sync status of all agents: active config version vs desired, with a drift indicator.

**Canary deploy (pro mode).** Large config changes can be rolled out gradually: apply to one agent or one group first, monitor, then roll out to all — one click from the UI.

**Agent binary** updates follow the same pattern in a later phase (Phase 3): the server stores a cosign-signed binary, the agent verifies the signature before self-updating. There is never an update without cryptographic verification.

---

## 13. Healthcheck & Self-Monitoring

A security system that stops silently is more dangerous than having no system at all, because it gives a false sense of security. DeusWatch monitors itself on two sides:

**Agent side: heartbeat.** Each agent sends a lightweight heartbeat every 30 seconds (configurable) over the same mTLS connection — containing collector status, buffer lag, the agent's CPU/RAM usage, and the active config version. Agent status on the dashboard: `online` → `degraded` (heartbeat arrives but a collector has an error / the buffer is piling up) → `disconnected` (3× heartbeats missed) → `stale` (offline > 24 hours). The transition to `disconnected` automatically produces a **`high`-severity alert** sent over the notification channels (section 11) — because a dead agent can mean two things: a technical problem, or **an attacker killing it to erase their tracks**. The agent also has a local watchdog: if the collector process crashes, an internal supervisor restarts it and reports the incident. On reconnect, the agent ships logs held in the local disk buffer while offline (store-and-forward) — no logs are lost from a brief connection drop.

**Server side: every component watches the others.** All services (gateway, worker, API) expose `/healthz` (liveness) and `/readyz` (dependencies ready: Postgres reachable, NATS connected) endpoints used by the Docker healthcheck to auto-restart a stuck container. On top of that, a single **internal monitor** checks vital metrics every minute: NATS consumer lag per stream (detects a worker that is alive but not working), ingest rate vs database write rate, disk usage (connected to the janitor in section 8), Postgres replication status, and enrichment/LLM job delays. Any anomaly becomes an internal alert labeled `deuswatch.label = selfhealth` that flows through the same alert pipeline — so system health issues appear on the dashboard and in Telegram exactly like attack alerts.

**System Health page in the UI.** One concise screen: the status of all containers, all agents (with a status map), real-time pipeline throughput, and a health incident history — so the question "why have logs from server X not arrived since yesterday?" is answered in five seconds, not through a debugging session.

---

## 14. Sustainability & Funding (DECIDED)

Donation channels: **Saweria** (Indonesian audience — QRIS/GoPay/OVO, withdraw directly to a local bank account) + **Ko-fi** (international audience — comes in via PayPal, withdraw to an Indonesian account). Both are registered in `.github/FUNDING.yml` so GitHub shows the Sponsor button automatically on the repo.

Placement in the product is subtle, never disrupting the analyst's workflow: a small "♥ Support DeusWatch" link in the sidebar footer and on the About/Settings page, plus one line in the README. No popups, banners, or nag screens of any kind.

The long-term monetization path if the project grows: an **open-core hosted** model — self-host free forever (AGPL), a paid cloud version for those who don't want to manage their own server (the Plausible/Cal.com model). This is one of the strong reasons for choosing the AGPL-3.0 license.

---

## 15. Decision Status & First Steps in Claude Code

**All design decisions are final:** the name **DeusWatch** (Go module: `github.com/<username>/deuswatch`), license **AGPL-3.0**, log schema **DCS** (an ECS-named subset + `deuswatch.*` namespace, section 7), minimum hardware target 2 vCPU / 2 GB RAM / 20 GB disk (recommended 2 vCPU / 4 GB / 50 GB; a local LLM via Ollama is outside this count and needs 8 GB+ on its own — that is the reason for the provider-agnostic design), funding via Saweria + Ko-fi in `FUNDING.yml`.

**First steps in Claude Code, in order:** (1) init the Go monorepo per the structure in section 5, along with the AGPL-3.0 LICENSE, a README skeleton, SECURITY.md, and `.github/FUNDING.yml`; (2) a docker-compose skeleton containing PostgreSQL+TimescaleDB, NATS JetStream, and one hello-world Go service; (3) an automatic mTLS certificate generation script, then prove two Go services talk to each other over mTLS; (4) define DCS in `internal/ingest/schema.go` + the first SQL migration (per-day-chunk hypertable); (5) only after that foundation is alive, start the Phase 1 features from the Linux agent. Foundation first, features later — and don't let sections 7–14 tempt you out of the Phase 1 scope.
