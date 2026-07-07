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

### Network containment (host isolation)

The IP-ban engine blocks an external attacker's IP. **Network containment** does the opposite:
it isolates one of **your own** agent hosts from the LAN (everything except the manager) to
stop lateral spread when that host is compromised. It fires only for rules that carry a
`mitigation_action: network_containment` block (e.g. ransomware shadow-copy deletion, or a
**webshell / PHP dropped in a web upload dir**). Two enforcement points, best-effort together:
host self-isolation (the agent applies its own firewall) plus an optional edge IP block.

- Auto vs recommend: with `CONTAINMENT_AUTO=1` and the alert severity at/above the rule's
  `criticality_threshold`, the host is isolated **immediately**; otherwise it becomes a
  **recommended** containment awaiting one-click approval (safe default). Auto-release after the
  rule's `timeout`.
- Example - a webshell drop: dropping `shell.php` into `/var/www/html/wp-content/uploads/`
  raises a **critical** alert (with `location:` = the file) and, via the
  `webshell_upload_containment` rule, isolates the web server. Needs FIM watching the web root
  and an agent that can self-isolate (Linux/Windows).

### Trusted-session gate (official change vs attack)

Since a file-change event carries **no source IP** (the OS reports *what* changed, not *who*),
the IP whitelist alone cannot tell a legit deploy/content edit from an attack. The gate bridges
that: when a **plain file-change alert** fires (e.g. `index.php` edited), the worker checks
whether that host had a **successful login from a whitelisted IP** within
`FILE_CHANGE_TRUSTED_WINDOW`. If so, it is an **official change** and the alert is **suppressed**
(the raw event is still stored); otherwise it alerts as normal. Two guardrails: it never gates
alerts that authorize **containment** (a webshell in an uploads dir still fires), and it does
nothing when the IP whitelist is empty. It relies on the login being reported to DeusWatch
(SSH via the agent), so keep 2FA/audit on trusted hosts - a stolen credential from a whitelisted
IP would pass the gate.

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
- `CONTAINMENT_AUTO=1` - auto-isolate on containment rules (else recommend-only).
- `FILE_CHANGE_TRUSTED_WINDOW` - trusted-session gate window (default `15m`).

Live in the **UI** (no restart): the ban ladder, permanent cap, observation window,
auto-approve toggle, and the IP whitelist. Enforcement targets (MikroTik/CrowdSec creds) are
configured in [Integrations](07-integrations.md).
