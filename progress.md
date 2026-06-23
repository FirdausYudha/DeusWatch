# DeusWatch — Progress & Handoff

> Progress notes for continuing on another machine. Design source of truth: [DeusWatch.md](DeusWatch.md).
> Last updated: 2026-06-22.

## Status summary

The security detection platform **runs end-to-end**, Phases 1–3 complete **plus a Phase 4
admin/UX layer** (granular RBAC, Integrations registry, central agent management +
enrollment wizard, Tier-2 ticketing, customizable drag-and-drop dashboard). The **entire
codebase is in English** (i18n pass done — UI, Go comments/logs/errors, tests, SQL, Sigma
YAML, docs). Stack: Go (agent/gateway/worker/api), PostgreSQL+TimescaleDB, NATS JetStream,
React+Vite+Tailwind. Verified live: the pipeline event→detection(Sigma single+aggregation)→
enrich→alert→response(dry-run)→LLM triage→report.

```
agent ──mTLS──▶ gateway ──▶ NATS ──▶ worker(enrich+detect) ──▶ TimescaleDB ──▶ API ──▶ Web UI
```

## Done & verified

| Area | Contents | Status |
|---|---|---|
| Foundation | monorepo, docker-compose (db/nats/api), cross-OS mTLS (CA+cert) | ✅ |
| DCS schema | `internal/ingest/schema.go` + TimescaleDB hypertable (chunk/day, compression, retention) | ✅ |
| Pipeline | `internal/bus` (NATS), `internal/store` (pgx), `internal/worker` | ✅ |
| Ingest | mTLS gateway + sshd normalization → DCS; agent tail → ship | ✅ |
| Detection | single-event Sigma (field/keyword/alias/MITRE) + **Sigma→SQL aggregation path** (compiles to a TimescaleDB query, periodic runner+cooldown+dry-run), `rules/sigma/` (+`agg/`) | ✅ |
| CTI enrichment | `internal/enrich` + Postgres TTL cache + **real AbuseIPDB/OTX clients + GeoIP** (ip-api) + configurable escalation + **community blocklist** | ✅ + shown in UI |
| **Response engine** (Phase 2) | `internal/respond`: nftables/CrowdSec/Mikrotik + dry-run + **progressive ban** + approval workflow (API) | ✅ |
| **Notifications** (Phase 2) | `internal/notify`: Telegram/email/webhook + dedup/throttle | ✅ |
| **LLM worker** (Phase 3) | `internal/llm`: triage alert→verdict (Claude SDK / heuristic) → `deuswatch.llm.*` | ✅ + UI |
| **Report** (Phase 3) | `internal/report` + `GET /api/report` (JSON/Markdown) | ✅ |
| Auth | login, sessions, **RBAC**, **append-only audit log**, user management, **TOTP 2FA** | ✅ + UI |
| Web UI | Login, Dashboard, **Agents**, **Integrations**, **Tickets**, Users, Settings, Response, Report | ✅ |
| Agent | per-agent enrollment, config push, heartbeat+offline buffer, **FIM**, **native Windows Service**, per-OS collectors, cross-compile | ✅ |
| Infra | **automatic migration runner** (embed), **CI** (vet/test/govulncheck/gosec/web), pinned images, gateway+worker in compose | ✅ |
| **Granular RBAC** (Phase 4) | per-user permission overrides on top of roles (`users.permissions`), checklist UI, menus gated by permission; catalog `internal/auth/rbac.go` | ✅ + UI |
| **Integrations** (Phase 4) | admin-managed registry (`internal/integrations`): MikroTik / CrowdSec / nftables-agent / AbuseIPDB / OTX; secrets AES-256-GCM encrypted at rest (`internal/secret`, `SECRETS_KEY`), write-only | ✅ + UI |
| **Agent mgmt** (Phase 4) | central monitoring config (sources + per-source scan `interval`), Wazuh-style OS/arch enrollment wizard | ✅ + UI |
| **Ticketing/DFIR** (Phase 4) | `internal/tickets`: open→in_progress→resolved→closed, assignee, case notes, time-to-resolve; "+ Ticket" from an alert | ✅ + UI |
| **Customizable dashboard** (Phase 4) | per-user widget layout (`user_dashboards`), `GET /api/dashboard` series + timeline; SVG widgets (stat/bar/donut/line/table/attack-map), edit mode with **drag-and-drop** reorder, type/color/size | ✅ + UI |

All tests (unit + integration + e2e) pass; gosec & govulncheck clean. Sigma ADR: [docs/adr/0001-sigma-detection-engine.md](docs/adr/0001-sigma-detection-engine.md).

## Phase 4 notes (admin & UX)

- **Migrations 000007–000010**: `users.permissions text[]` (RBAC), `integrations`, `tickets`+`ticket_comments`, `user_dashboards`.
- **Permissions**: `view_dashboard, ack_alert, approve_remediation, execute_block, view_tickets, manage_tickets, manage_rules, manage_agents, manage_integrations, manage_users, manage_settings`. Roles: viewer=dashboard; analyst=+ack/approve/tickets; admin=all. NULL `users.permissions` = inherit role, non-NULL = explicit custom set. `GET /api/permissions` = catalog + role defaults; `PUT /api/users/{id}` updates role/perms.
- **Secrets**: `internal/secret` AES-256-GCM via `SECRETS_KEY` (base64 32 bytes); no key → DEV key + warning. Integration secret fields encrypted at rest, never returned (a `secrets_set` map flags which are set); blank-on-edit preserves them.
- **Integrations enforcement is wired** — the worker builds the CTI provider & MikroTik responder from the registry (`resolveCTIKeys`/`resolveResponder`, DB > env). Agent-side nftables auto-block: gateway `GET /v1/blocklist` (mTLS) serves the response engine's active blocks when an `nftables_agent` integration is enabled; the agent polls it (`AGENT_FIREWALL=nftables`) and applies to a local nft set (`internal/agent/firewall_linux.go`, root/CAP_NET_ADMIN; Linux only). Manager side verified over mTLS; nft application runs on a real Linux agent.
- **Agent intensity**: `agent.Source.Interval` (seconds) honoured by poll collectors (fim, wineventlog) via `Source.scanInterval`; file/journald stay live-streamed.
- **Dashboard**: drag a widget by its ⠿ grip (native HTML5 DnD) to reorder; layout persists per user. Free-form X/Y positioning + drag-to-resize would need `react-grid-layout` (not added).
- **Logo**: `web/public/deuswatch-eye.png` (resized) in sidebar + login; source art in `logo/`.

## Prerequisites on a new PC

- **Go 1.25+** (developed with 1.26)
- **Docker Desktop**
- **Node 22+** (for the web UI)

## Setup on a new PC — ONE COMMAND

```bash
git clone https://github.com/FirdausYudha/DeusWatch.git
cd DeusWatch
docker compose -f deploy/docker-compose.yml up -d --build
```

That's it. Compose brings up **everything**: db, nats, **certgen** (init: generates the
mTLS certificates into `deploy/certs`, idempotent), api (auto-migrate), gateway, worker, and **web** (nginx).

- **Web UI:** http://localhost:5173 · **API:** http://localhost:8080
- **Dev login:** `admin` / `thewatcher` (auto-seeded; change via `ADMIN_PASSWORD`).
- **Self-registration** is enabled on the login page (new account = viewer role). Disable with: `REGISTRATION_ENABLED=0`.

> Web dev hot-reload (optional): `cd web && npm install && npm run dev` → :5173 — do NOT
> run it alongside the `web` container (port clash); turn off one of them.
> Manual migrate if needed: `DATABASE_URL=... go run ./cmd/migrate`. Regen certs: `go run ./cmd/certgen --out deploy/certs -force`.

## Running the full pipeline (local agent)

gateway/worker are now **already in docker-compose** (step 1 starts them). Only the
**agent** runs on a separate endpoint. To run the binaries locally (dev), set the env
then run (PowerShell example in `bin/`):

```
NATS_URL=nats://localhost:4222
STORE_DSN=postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable
CERT_DIR=deploy/certs            # gateway/worker use the server cert + CA
RULES_DIR=rules/sigma
GATEWAY_ADDR=:8443

go build -o bin/gateway.exe ./cmd/gateway   # + worker, agent
# run gateway, worker, then agent (agent: GATEWAY_URL=https://localhost:8443)
```

Cross-compile the agent for all OSes: `./scripts/build-agent.sh` → `dist/`.
Install the agent: `deploy/agent/` (systemd `install-linux.sh`, Windows `install-windows.ps1`).

### Agent enrollment flow (Wazuh-style)
1. Admin creates a token: `POST /api/agents/tokens` (Bearer admin) → `{token}`.
2. Agent exchanges the token: `agent -enroll -token <T> -name <name> -manager http://host:8080 -out <certdir>`.
3. The agent runs normally with that cert; it shows up in `GET /api/agents`; it can be revoked.
4. Config push: admin `PUT /api/agents/{id}/config {sources:[...]}`; the agent fetches it via the gateway at start + poll (version increases → restart to apply).

## Important notes/gotchas

- **Automatic migrations** — in-house runner (`internal/migrate` + embed in the `migrations` package); the api applies them at start (idempotent). Standalone: `cmd/migrate`. `RUN_MIGRATIONS=0` to disable.
- **Pinned images**: timescaledb `2.17.2-pg16`, nats `2.10.22-alpine`. Changing the pin on an old volume created by a different version can clash — use a fresh volume.
- **CI**: `.github/workflows/ci.yml` (vet/build/test with pg+nats services, govulncheck, gosec, web tsc+build). gosec excludes rules inherent to the domain (see the workflow).
- **Response engine**: `RESPONDER=dryrun|nftables|crowdsec|mikrotik|none` (default dryrun). nftables/crowdsec/mikrotik are WRAPPED in dry-run unless `RESPONSE_LIVE=1`. `RESPONSE_AUTO_APPROVE=1` executes without approval. Approve/dismiss via `POST /api/responses/{id}/approve|dismiss`.
- **Notifications**: active when any channel is filled in — `TELEGRAM_BOT_TOKEN`+`TELEGRAM_CHAT_ID`, `WEBHOOK_URL`, or `SMTP_HOST`+`SMTP_FROM`+`SMTP_TO`(+`SMTP_USER`/`SMTP_PASS`). Threshold `NOTIFY_MIN_SEVERITY` (default high), dedup `NOTIFY_THROTTLE` (default 10m, per rule+IP). The worker calls it via `worker.AlertHook` (alongside the response engine).
- **LLM worker** (Phase 3): `ANTHROPIC_API_KEY` → Claude analyzer (model `ANTHROPIC_MODEL`, default `claude-opus-4-8`, via the official SDK); `LLM_ENABLED=1` → offline heuristic analyzer. The worker polls alerts without a verdict every 20s → fills `deuswatch.llm.*`.
- **Report**: `GET /api/report?hours=24` (JSON) or `?format=md` (Markdown) — a summary of events/alerts/severity/top IP/rule/MITRE/verdict.
- **Community blocklist**: `BLOCKLIST_URLS` (comma-separated IP/CIDR feeds) → matching IPs are marked abuse=100 (feed `blocklist`); refresh every `BLOCKLIST_REFRESH` (default 6h).
- **Real CTI enrichment**: set `ABUSEIPDB_API_KEY` / `OTX_API_KEY` / `GEOIP_ENABLED=1` in the worker env (without them a mock provider is used). Escalation thresholds: `ABUSE_ESCALATE_THRESHOLD` (default 90), `OTX_ESCALATE_THRESHOLD` (default 5).
- **bin/ & dist/ & deploy/certs/ are gitignored** — rebuild binaries & regen certs on a new PC.
- When changing service code, **rebuild the binaries** before a demo (some demo bugs were from stale binaries).
- `gateway` needs `STORE_DSN` for revocation/config-push/heartbeat (optional; without a DB those features are off).
- **Cross-host mTLS**: the agent trusts the manager by the private CA, not by hostname/IP (`mtls.ClientConfig` verifies the chain via `VerifyPeerCertificate`, no SAN name check), so agents on other hosts connect without per-IP cert tweaks. `MANAGER_IP` (deploy/.env) optionally pins the IP into the server-cert SAN. Regen certs + re-enrol agents when the CA changes. See README "Deploying agents".
- The `detect-worker` detector… the durable NATS consumer uses DeliverNew (no backlog replay).
- The single-event Sigma engine = an interim evaluator; the aggregation path = an in-Go compiler to SQL (ADR 0001 addendum).
- Changing the TimescaleDB image pin on an old volume created by a different version → clash (`$libdir`); use a fresh volume.

## Main roadmap (Phases 1–3) — DONE ✅

The following seven roadmap items are implemented, tested, and verified end-to-end:
Sigma aggregation→SQL+new rules (#4); FIM+native Windows Service+Agents page (#5);
real CTI clients+GeoIP+UI (#6); response engine+progressive ban (#7); infra migration/CI/
compose (#8); notifications (#9); LLM worker+report+blocklist (#10).

## Phase 4 (admin & UX) — DONE ✅

Full i18n (codebase → English); granular per-user RBAC; Integrations registry (encrypted
secrets); central agent monitoring config + OS/arch enrollment wizard; Tier-2 DFIR
ticketing; customizable drag-and-drop dashboard; eye logo wired in.

## Follow-up ideas

- Enforcement wiring is **done** (CTI/MikroTik from registry; agent nftables block feed).
  Possible refinements: per-agent block scoping (gateway filters by `agent_scope` + CN);
  CrowdSec/Mikrotik config fully from DB; run the agent nft applier on a real Linux box.
- Dashboard: free-form X/Y + drag-to-resize via `react-grid-layout`; a real geographic
  world map for the attack-origins widget.
- Sigma: mature Go fork for single-event; expand datasets (process/web); rules from the UI.
- Agent: canary config deploy, real-time FIM (fsnotify) instead of polling.
- pgvector for RAG/LLM (the embedding column is prepared in the schema).

## Commit map (newest → oldest, partial)

```
feat(dashboard): drag-and-drop widget reordering
feat(dashboard): customizable Kibana-style widget dashboard
feat(tickets): Tier-2 DFIR ticketing + logo
feat(agents): central monitoring config + OS/arch enrollment wizard
feat(integrations): admin-managed connector registry
feat(rbac): per-user granular permissions (checklist)
i18n: translate entire codebase to English (UI, Go, SQL, rules, docs)
(#10) feat(llm): LLM worker + report + community blocklist (Phase 3)
(#9)  feat(notify): Telegram/email/webhook + dedup/throttle
(#8)  feat(infra): automatic migration runner + CI + gateway/worker in compose
(#7)  feat(respond): response engine + block + approval + progressive ban
(#6)  feat(enrich): real AbuseIPDB/OTX clients + GeoIP + shown in UI
(#5)  feat(agent): FIM + native Windows Service + Agents UI page
(#4)  feat(detect): Sigma->SQL aggregation path + new rules
... (Phase 1: auth/agent/enrich/UI/pipeline/foundation) — see `git log`
```
