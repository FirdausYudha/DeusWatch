# 2. Response (SOAR)

Turns alerts into block recommendations, lets you approve/dismiss/**unban**, and enforces
bans on real devices via the **progressive-ban** engine.

## How it works

- The **worker** produces a block recommendation when an alert has a source IP (respecting the
  IP whitelist and per-offender dedup). Repeat offenders escalate down a configurable duration
  ladder (e.g. `10m → 30m → 1h → 24h → permanent`).
- A recommendation is `recommended` until approved. On **approve** (or auto-approve), the
  engine calls the configured **Responder** (`nftables` agent-side / `MikroTik` / `CrowdSec`)
  to `Block(ip, ttl)` and marks it `executed`. **Unban** calls `Unblock(ip)` and marks it
  `unbanned`.
- All state lives in the `response_actions` table.

## How to use

Two views (toggle top-right):

- **By IP** - per-offender rollup; approve/dismiss, or bulk-dismiss all pending for one IP.
  Shows the **Agent** whose alert last triggered a block for that IP.
- **Events** - every action as a row (with the triggering **Agent**):
  - **Search bar** - free-text over IP / rule / reason.
  - **Checkboxes + select-all** - pick many rows, then **Approve / Dismiss / Unban selected**.
  - Per-row **Approve/Dismiss** (recommended) or **Unban** (executed/approved block).
  - Status filter: All / Recommended / Executed / Dismissed / Unbanned / Failed.
- **Ban policy editor** - edit the ladder, permanent cap, observation window, auto-approve.
- **IP whitelist** - CIDRs that are never banned.

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/responses?status=&q=` | list/search actions | `view_dashboard` |
| `GET /api/responses/offenders` | per-IP rollup | `view_dashboard` |
| `POST /api/responses/{id}/approve` | approve + execute | `approve_remediation` |
| `POST /api/responses/{id}/dismiss` | dismiss a recommendation | `approve_remediation` |
| `POST /api/responses/{id}/unban` | lift an active block | `approve_remediation` |
| `POST /api/responses/dismiss-ip` | bulk-dismiss for an IP | `approve_remediation` |
| `GET/PUT /api/ban-policy`, `GET/POST/DELETE /api/whitelist` | policy & whitelist | `manage_settings` |

Frontend: [`web/src/response/`](../../web/src/response/). Engine:
[`internal/respond/`](../../internal/respond/).

## Ports / tech

- Browser → Web `9173` → API `9080`. The actual blocking happens where the Responder lives
  (the agent's host firewall, or MikroTik/CrowdSec over their own APIs).
- Language: Go (engine + responders), React/TypeScript (UI).

## Variables

In `deploy/.env` (worker):
- `RESPONDER` - `dryrun` (default, log only), or a real driver via Integrations.
- `RESPONSE_LIVE=1` - actually enforce (otherwise dry-run).
- `RESPONSE_AUTO_APPROVE=1` - skip manual approval.

Live in the **UI** (no restart): the ban ladder, permanent cap, observation window,
auto-approve toggle, and the IP whitelist. Enforcement targets (MikroTik/CrowdSec creds) are
configured in [Integrations](07-integrations.md).
