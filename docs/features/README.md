# DeusWatch - Feature modules

Per-menu documentation. Each module explains **how it works**, **how to use it**, **which
ports it uses**, **what language/tech it's built with**, and **how to change its variables**.

| # | Module | What it's for |
|---|---|---|
| 1 | [Dashboard](01-dashboard.md) | Live overview: stats, charts, attack map, searchable events/alerts, system & storage health |
| 2 | [Response](02-response.md) | Progressive-ban recommendations, approve/dismiss/**unban**, search, bulk actions |
| 3 | [Tickets](03-tickets.md) | Tier-2 case management (open → resolved) with comments |
| 4 | [Report](04-report.md) | Security summary + AI executive summary (on-demand/scheduled) + delivery/export |
| 5 | [Agents](05-agents.md) | Enroll endpoints (Linux/Windows), one-line installer, revoke, config push |
| 6 | [Rules](06-rules.md) | DB-backed Sigma detection rules, managed from the UI |
| 7 | [Integrations](07-integrations.md) | Connectors: CTI, firewall/bouncer, LLM, FIM reputation, export |
| 8 | [Users](08-users.md) | Accounts, RBAC roles & permissions, audit trail |
| 9 | [Settings](09-settings.md) | 2FA, password, notifications, storage lifecycle, config profile, updates |
| 10 | [Network Containment](10-network-containment.md) | Isolate a compromised host from the LAN (host self-isolation + edge block) |
| 11 | [Decoders](11-decoders.md) | Data-driven regex log parsing for sources without a built-in decoder (Wazuh-style) |
| 12 | [Playbooks](12-playbooks.md) | Per-label remediation playbooks stamped onto every alert (UI-editable catalog) |

---

## Shared architecture (applies to every module)

```
Browser ──HTTP──> Web (nginx, React) ──/api proxy──> API (Go)
                                                       │
Agent ──mTLS──> Gateway (Go) ──> NATS JetStream ──> Worker (Go) ──> PostgreSQL + TimescaleDB
                                                                          ▲
                                                          API reads/writes the same DB
```

- **Every menu in the web UI** talks to the **API** over HTTP (`/api/...`). The API is the
  single source of truth; it reads/writes PostgreSQL and (for a few endpoints) reaches
  external services (GitHub, AbuseIPDB, …).
- **Agents** are the only component that uses the **Gateway** (mTLS), not the API, for
  shipping logs - see the [Agents](05-agents.md) module.

## Languages / tech

| Layer | Tech |
|---|---|
| Backend (api, gateway, worker, agent) | **Go** |
| Frontend (all 9 menus) | **React + Vite + TypeScript + Tailwind** |
| Database / log store | **PostgreSQL 16 + TimescaleDB** |
| Message bus | **NATS JetStream** |
| Packaging | **Docker Compose** (each service = one container) |

There is **no Python runtime** - connectors are compiled Go drivers (see
[Integrations](07-integrations.md)).

## Ports

Host-published ports (defaults; override in `deploy/.env`). Containers always listen on their
internal port - you only remap the host side.

| Service | Internal | Host default | Env var to change | Used by |
|---|---|---|---|---|
| Web UI | 80 | **9173** | `DEUSWATCH_WEB_PORT` | all menus (browser) |
| API | 8080 | **9080** | `DEUSWATCH_API_PORT` | all menus + agent enroll/install |
| Gateway (mTLS) | 8443 | **9443** | `DEUSWATCH_GATEWAY_PORT` | Agents (log ingest) |
| PostgreSQL | 5432 | **5432** | `DEUSWATCH_DB_PORT` | internal |
| NATS | 4222 / 8222 | 4222 / 8222 | (compose) | internal |

## How to change variables (two places)

1. **Server env - `deploy/.env`** (secrets & infrastructure): ports, DB password,
   `SECRETS_KEY`, CTI/SMTP/Telegram credentials, `MANAGER_IP`, etc. Apply with:
   ```bash
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
   ```
   Full list + comments: [`deploy/.env.example`](../../deploy/.env.example).
2. **UI / database** (behaviour, live - no restart): detection rules, ban policy, whitelist,
   alert threshold, report schedule, storage retention, integrations (including the CTI cache
   window on each CTI connector). These are stored in the DB and edited from the relevant menu.

## Access control (RBAC)

Three roles: **viewer** (read-only), **analyst** (investigate + approve remediation),
**admin** (full). Each API endpoint requires a permission (e.g. `manage_rules`). See
[Users](08-users.md) for the role→permission matrix.
