# 6. Rules

DB-backed **Sigma** detection rules, fully managed from the UI (Wazuh-style): browse, edit,
toggle, add, delete.

## How it works

- Rules are **Sigma YAML** stored in the `rules` table, classified as **single-event** or
  **aggregation** (`count() by <field>` - e.g. brute force / port scan).
- Built-in rules (from `rules/sigma/`) are **seeded on first start**; new bundled rules are
  **auto-synced by name** on upgrade without touching your edits.
- The **worker loads the enabled set and live-reloads** it (~1 min) - edits in the UI take
  effect without a restart. Alerts are auto-labeled with **MITRE ATT&CK** from the rule's tags.
- Custom rules are **validated on save** (must parse as Sigma).

## How to use

- **Rules** menu → table of all rules (name, kind, enabled, builtin).
- **Toggle** to enable/disable; **Edit** the YAML; **Add** a custom rule (paste Sigma YAML);
  **Delete** custom rules.
- Single-event example matches one event; aggregation example: `count() by source.ip > 5` in a
  timeframe = brute force.

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/rules` | list all | `manage_rules` |
| `POST /api/rules` | create (validated) | `manage_rules` |
| `PUT /api/rules/{id}` | edit / toggle | `manage_rules` |
| `DELETE /api/rules/{id}` | delete | `manage_rules` |

Frontend: [`web/src/rules/`](../../web/src/rules/). Backend:
[`internal/rules/`](../../internal/rules/), Sigma engine
[`internal/detect/sigma/`](../../internal/detect/sigma/). Bundled rules:
[`rules/sigma/`](../../rules/sigma/).

## Ports / tech

- Browser → Web `9173` → API `9080`. Language: Go (Sigma parser + SQL compiler for
  aggregation), React/TypeScript (UI). Rules stored in PostgreSQL.

## Variables

- No env for the rules themselves - they live in the DB and are edited in the UI (live-reload).
- `RULES_DIR` (worker/api env) points at the bundled rules dir used for seeding/sync (default
  `/rules/sigma`).
- To ship a new built-in rule to an existing deployment: add the `.yml` to `rules/sigma/`,
  update, and it's auto-synced. To tweak one rule now, just edit it in the UI.
