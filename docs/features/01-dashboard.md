# 1. Dashboard

The landing view: a live picture of what's happening, plus a searchable events/alerts table
and health panels.

## How it works

- The React page polls the API every ~5s: `GET /api/dashboard` (widget data for the chosen
  time range), `GET /api/events/search` (the table), `GET /healthz` + `GET /api/storage/status`
  (health panels).
- The API reads aggregates from the `events` hypertable in PostgreSQL/TimescaleDB. Nothing is
  computed in the browser beyond layout.
- Widgets are **drag-and-drop customizable**; your layout is saved per-deployment via
  `GET/PUT /api/dashboard/layout`.

## How to use

- **Time range**: use the presets (`1h/6h/24h/7d/30d`) or the calendar for a custom window.
- **Search bar (top)**: free-text - matches source **IP**, rule name/id, MITRE technique, host,
  user, file path, label, and raw message. Tick **Alerts only** to hide raw info events.
- **Filters panel**: narrow by Source IP, Rule, MITRE ID, Min level, From/To.
- **Webhook** button: POST the current events/alerts as JSON to your export webhook.
- **Customize**: rearrange/add/remove widgets, then Save.
- **Log Storage** panel: DB size vs budget, retention lifecycle, replication status.

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/dashboard` | widget aggregates for a range | `view_dashboard` |
| `GET /api/dashboard/layout`, `PUT` | saved widget layout | `view_dashboard` / `manage_settings` |
| `GET /api/events/search` | searchable events/alerts table | `view_dashboard` |
| `GET /api/storage/status` | storage/replication health | `view_dashboard` |
| `POST /api/export/events` | send events/alerts to export webhook | `view_dashboard` |

Frontend: [`web/src/dashboard/`](../../web/src/dashboard/). Backend query:
[`internal/store/query.go`](../../internal/store/query.go).

## Ports / tech

- Browser → **Web `9173`** → API **`9080`**. Language: React/TypeScript (UI), Go (API).
- See the [shared ports table](README.md#ports).

## Variables

- Mostly nothing to configure - it visualizes whatever the pipeline produces.
- Storage budget/alert (shown in the Log Storage panel) come from `STORAGE_BUDGET_GB` /
  `STORAGE_ALERT_PERCENT` in `deploy/.env` - see [Settings](09-settings.md).
- The dashboard layout is saved in the DB (per deployment), edited via the **Customize** button.
