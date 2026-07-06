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

## Log sources a rule needs

A rule only fires if the pipeline produces the matching events. Coverage by category:

| Rule category | Fires from | Log source (agent) |
|---|---|---|
| SSH / auth (brute force, invalid user, sudo) | `sshd` events | `/var/log/auth.log` (default) |
| FIM (file change, malicious hash, monitored dirs) | `fim` events | agent FIM watcher |
| Port scan | `firewall` drops | `/var/log/ufw.log` (default; enable firewall logging) |
| Windows logon (4625/4624/4740) | `windows-security` | Windows agent Event Log |
| **Web (defacement, judi-online, path scan)** | **`web` events** | **`/var/log/nginx/access.log` (default)** - keyword rules match the raw request line; the client IP is extracted for banning. For apache add `/var/log/apache2/access.log` via the agent config. |

> Process/EDR rules (`category: process_creation`) need a process-audit source (auditd/sysmon)
> which is not shipped yet - those rules are present but stay dormant until such a source exists.

## Variables

- No env for the rules themselves - they live in the DB and are edited in the UI (live-reload).
- `RULES_DIR` (worker/api env) points at the bundled rules dir used for seeding/sync (default
  `/rules/sigma`).
- To ship a new built-in rule to an existing deployment: add the `.yml` to `rules/sigma/`,
  update, and it's auto-synced. To tweak one rule now, just edit it in the UI.
