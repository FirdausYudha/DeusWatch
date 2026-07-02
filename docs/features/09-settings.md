# 9. Settings

Per-account security plus deployment-wide, UI-managed configuration. Most sections write to the
DB and are picked up live (no restart).

## Sections & how they work

| Section | What it does | Stored in | Live? |
|---|---|---|---|
| **Two-Factor (TOTP)** | enable/disable 2FA for your account | `users` | yes |
| **Change password** | rotate your password (Argon2id) | `users` | yes |
| **Alert notifications** | severity threshold for Telegram/email alerts | `notify_config` | ~1 min |
| **Log storage lifecycle** | retention (days) + compression (days) — TimescaleDB policy | policy | immediate |
| **Threat-intel (CTI) caching** | dedup window (hours) + shows provider status (real/mock) | `cti_config` | ~1 min |
| **Software updates** | check GitHub for a newer build (read-only) | — | on click |
| **Config profile** | export/import all settings to clone server A → B | JSON | on import |

- **Alert notifications / CTI caching / retention** are read live by the worker (threshold +
  TTL reload each minute; retention re-applies the TimescaleDB policy on save).
- **Software updates** only *checks* (compares the baked git commit vs GitHub's latest). The
  update itself runs on the host with `./scripts/update.sh` — the web app never controls Docker,
  by design (small attack surface).
- **Config profile** exports rules, ban policy, whitelist, AI-report schedule, notification
  settings, and integrations (secrets excluded) as JSON to import onto another server.

## How to use

- Open **Settings**; each card is self-explanatory. Admin-only cards require `manage_settings`.
- To update the software: click **Check for update**; if behind, run `./scripts/update.sh` on
  the host (or a cron — see below).

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `POST /api/2fa/setup` / `enable` / `disable` | 2FA | auth |
| `PUT /api/me/password` | change password | auth |
| `GET/PUT /api/notify-config` | alert threshold + delivery | `view_dashboard` / `manage_settings` |
| `GET /api/storage/status`, `PUT /api/storage/retention` | storage + lifecycle | `view_dashboard` / `manage_settings` |
| `GET/PUT /api/cti-config` | CTI cache TTL + status | `view_dashboard` / `manage_settings` |
| `GET /api/update-check` | update check (GitHub) | `view_dashboard` |
| `GET /api/config/export`, `POST /api/config/import` | config profile | `manage_settings` |

Frontend: [`web/src/settings/`](../../web/src/settings/).

## Ports / tech

- Browser → Web `9173` → API `9080`. `update-check` makes an outbound HTTPS call to GitHub from
  the API. Language: Go + React/TypeScript.

## Variables

- **Credentials & infra** in `deploy/.env`: `TELEGRAM_*`, `SMTP_*` (notification channels),
  `SECRETS_KEY`, `STORAGE_BUDGET_GB` / `STORAGE_ALERT_PERCENT`, ports.
- **Behaviour** in the UI (DB-backed, live): severity threshold, report/AI schedules, retention,
  compression, CTI cache TTL.
- **Auto-update (optional, host-level)** — a cron running the updater; the web UI does **not**
  execute updates:
  ```bash
  0 4 * * *  cd /path/to/DeusWatch && ./scripts/update.sh >> /var/log/deuswatch-update.log 2>&1
  ```
