# 3. Tickets

Lightweight Tier-2 case management: escalate an alert into a tracked ticket with a status
lifecycle and comments.

## How it works

- Tickets are rows in the `tickets` table (with `ticket_comments`). No external tracker.
- A ticket has: title, description, severity, status (`open → in_progress → resolved → closed`),
  assignee, linked source IP / rule id, and timestamps.
- From an alert on the Dashboard you can **Create ticket** - it pre-fills the form.

## How to use

- **Tickets** menu → list of cases; open one to see details + comment thread.
- **New ticket**: title, description, severity, (optional) assignee/source IP/rule.
- Change **status** and **assignee** as the case progresses; add **comments** for the trail.
- Filter/scan by status.

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/tickets` | list | `view_tickets` |
| `GET /api/tickets/{id}` | one ticket + comments | `view_tickets` |
| `POST /api/tickets` | create | `manage_tickets` |
| `PUT /api/tickets/{id}` | update status/assignee/fields | `manage_tickets` |
| `POST /api/tickets/{id}/comments` | add a comment | `manage_tickets` |

Frontend: [`web/src/tickets/`](../../web/src/tickets/). Backend:
[`internal/tickets/`](../../internal/tickets/).

## Ports / tech

- Browser → Web `9173` → API `9080`. Language: Go (API), React/TypeScript (UI). Data in
  PostgreSQL.

## Variables

- No env configuration. Everything (tickets, comments, status) is stored in the DB and managed
  from the UI.
- Access is role-gated: **viewer** cannot see tickets; **analyst/admin** can view; creating and
  editing needs `manage_tickets`.
