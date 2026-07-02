# 8. Users

Accounts, role-based access control (RBAC), and the audit trail.

## How it works

- Users live in the DB; passwords hashed with **Argon2id**. Login returns a **session token**
  (rotating, sent as `Authorization: Bearer …`), not a long-lived JWT.
- **RBAC**: every API endpoint requires a permission; a user's role grants a set of
  permissions. Optional **TOTP 2FA** per account.
- Every state-changing action is written to an **append-only audit log** (actor, role, action,
  target, IP).

## Roles → permissions

| Permission | viewer | analyst | admin |
|---|:--:|:--:|:--:|
| `view_dashboard` | ✅ | ✅ | ✅ |
| `ack_alert`, `approve_remediation`, `execute_block` | ❌ | ✅ | ✅ |
| `view_tickets`, `manage_tickets` | ❌ | ✅ | ✅ |
| `manage_rules` / `manage_agents` / `manage_integrations` | ❌ | ❌ | ✅ |
| `manage_users` / `manage_settings` | ❌ | ❌ | ✅ |

(Exact mapping: [`internal/auth/rbac.go`](../../internal/auth/rbac.go).)

## How to use

- **Users** menu (admin only): create users with a role, edit role, delete.
- Self-registration (if enabled) creates a **viewer** account from the login page.
- Each user manages their own **password** and **2FA** in [Settings](09-settings.md).

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `POST /api/login`, `/api/logout` | session | public / auth |
| `GET /api/me`, `PUT /api/me/password` | self | auth |
| `GET/POST /api/users`, `PUT/DELETE /api/users/{id}` | manage users | `manage_users` |
| `GET /api/permissions` | permission catalog | auth |
| `POST /api/register` | self-signup (if enabled) | public |

Frontend: [`web/src/users/`](../../web/src/users/). Backend:
[`internal/auth/`](../../internal/auth/).

## Ports / tech

- Browser → Web `9173` → API `9080`. Language: Go (auth, Argon2id, RBAC), React/TypeScript.

## Variables

In `deploy/.env`:
- `ADMIN_USERNAME` / `ADMIN_PASSWORD` - the initial admin, seeded only when the users table is
  empty (first start). Change the password later in Settings.
- `REGISTRATION_ENABLED` - `0` (default; admins create users) or `1` (allow viewer self-signup).

Roles/permissions are fixed in code (three built-in roles); users & their roles are managed in
the UI.
