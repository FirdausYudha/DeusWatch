# 4. Report

A security summary over a time window, an optional **AI executive summary**, and ways to
**deliver/export** it.

## How it works

- `GET /api/report?hours=N` builds the summary (totals, severity, top IPs/rules, MITRE, LLM
  verdicts) from the `events` hypertable - same data as the dashboard, presented for reading.
- **AI executive summary**: an LLM turns the report into a short narrative. Generated
  **on-demand** (button) or on a **schedule** by the worker; stored in `report_summaries`.
  Cost-controlled - the LLM runs on reports, not per alert.
- **Scheduled delivery** (separate from the AI schedule) sends the report text to
  Telegram/email on a cadence.

## How to use

- **Report** menu → pick a window (`24h / 7d / 30d`).
- **AI executive summary** box:
  - **Generate now** - needs an LLM integration (e.g. free local Ollama).
  - **Schedule** dropdown - `off / 24h / 3d / 7d / Custom` for auto-generation.
- **Scheduled delivery** - `off / 24h / 3d / 7d / Custom` to email/Telegram the report.
- **PDF** (print), **Markdown** (download), **Webhook** (POST JSON to the export webhook).

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/report?hours=` | the report (JSON/Markdown) | `view_dashboard` |
| `GET /api/report/summary` | latest stored AI summary | `view_dashboard` |
| `POST /api/report/summary` | generate AI summary now | `view_dashboard` |
| `GET/PUT /api/report/ai-config` | AI auto-generation schedule | `view_dashboard` / `manage_settings` |
| `GET/PUT /api/notify-config` | alert threshold + report delivery schedule | `view_dashboard` / `manage_settings` |
| `POST /api/export/report` | send report to export webhook | `view_dashboard` |

Frontend: [`web/src/report/`](../../web/src/report/). Backend:
[`internal/report/`](../../internal/report/), scheduler in [`cmd/worker/main.go`](../../cmd/worker/main.go).

## Ports / tech

- Browser → Web `9173` → API `9080`. The worker calls the LLM + Telegram/email. Language: Go
  + React/TypeScript.

## Variables

- **LLM** (for the AI summary): configured in [Integrations](07-integrations.md) (provider,
  base URL, model, key) - or env `ANTHROPIC_API_KEY` / `LLM_ENABLED`. To connect a free local
  Ollama and troubleshoot (DNS, nginx 504, slow model), see
  [docs/llm-ollama.md](../llm-ollama.md).
- **Delivery channels**: `TELEGRAM_*` / `SMTP_*` in `deploy/.env` (see
  [notifications](../notifications.md)).
- **Schedules** (AI + delivery): set live in the UI (stored in `report_ai_config` /
  `notify_config`).
