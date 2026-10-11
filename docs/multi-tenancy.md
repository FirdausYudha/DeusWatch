# Multi-Tenancy

DeusWatch can serve several client organizations from one deployment with **database-enforced** data
isolation. This page explains the model, the deployment requirements that keep isolation airtight, and
how to operate it.

## The model

- **Tenant**: the data-isolation boundary. Every agent, and all the telemetry it produces (events,
  scores, FIM snapshots, inventory, vulnerabilities, tickets), belongs to exactly one tenant.
- **Workspace**: a team. A workspace is granted access to one or more tenants (**many-to-many**: a
  workspace can reach several tenants, and a tenant can be shared with several workspaces).
- **User → Workspace → Tenant**: a user belongs to one or more workspaces; their effective tenant
  scope is the **union** of the tenants reached by those workspaces. An optional active-workspace
  selector (the switcher in the top bar) narrows the view to a single workspace.

A fresh install has a single **Default** tenant and **Default** workspace, with every existing user a
member, so a single-tenant deployment behaves exactly as before.

## How isolation is enforced (why a bug can't leak across tenants)

Isolation does **not** depend on every handler remembering to filter. Postgres enforces it:

- **Row-Level Security (RLS)**: fail-closed, on the tenant-scoped tables. Each request runs inside a
  transaction that sets `deuswatch.tenant_ids` (the caller's tenants) via `SET LOCAL`; the RLS policy
  is `USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))`. A path that forgets
  to open a scope sees an **empty** tenant set → **zero rows**, never someone else's data.
- **The `events` hypertable** can't carry RLS (TimescaleDB makes columnar compression and RLS mutually
  exclusive), so it is fronted by a **security-barrier view** named `events` over the compressed
  `events_data` hypertable, applying the identical fail-closed filter. Reads and writes go through the
  view transparently.
- **A restricted role.** The application connects as a superuser bootstrap role (`deuswatch`). it has
  to, to create the TimescaleDB extension etc. But **superusers bypass RLS entirely**, so scoped
  request transactions drop to a `NOSUPERUSER NOBYPASSRLS` role, **`deuswatch_app`**, via `SET LOCAL
  ROLE` (transaction-local, auto-reverting). That role is what the database actually constrains.
- **Boot gate.** The API refuses to start unless every scoped table is `ENABLE`d + `FORCE`d for RLS,
  the `events` view is present with `security_barrier` on, and `deuswatch_app` genuinely cannot bypass
  RLS. This catches a half-applied migration or a misconfigured role, the "silent total leak" failure
  mode. (Override only for a deliberate pre-migration rollback with `DEUSWATCH_SKIP_RLS_CHECK=1`.)

### Trusted system processes

The **worker** and **gateway** legitimately span all tenants (scoring the whole fleet, authenticating
every agent). They connect with `store.ConnectSuperadmin`, which sets `deuswatch.superadmin = '1'` at
the session level so their queries bypass RLS. The **platform super-admin** user (the `manage_tenants`
permission) is treated the same way per request, they see across all tenants, and the workspace
switcher does **not** narrow their view. Bypass means "spans all tenants", not "may blend them": the
worker's per-tenant scorers still `GROUP BY tenant_id`.

## Deployment requirements

1. **Run the migrations.** `000049` to `000054` create the tenant schema, stamp tenant IDs, enable RLS,
   create the `deuswatch_app` role and the `events` security-barrier view. The API auto-runs migrations
   at start (unless `RUN_MIGRATIONS=0`).
2. **The API connects as the owner/superuser role** (`deuswatch`). this is expected. Per-request
   scoping drops to `deuswatch_app`; you do not point the API at `deuswatch_app` directly.
   - If you instead run the API as a **non-superuser** login role, that role must be a member of
     `deuswatch_app` (`GRANT deuswatch_app TO <login_role>`) so `SET LOCAL ROLE` is permitted.
3. **Worker and gateway** use the super-admin connection automatically: no configuration needed.
4. Do not grant `BYPASSRLS` or superuser to `deuswatch_app`; the boot gate will refuse to start if you
   do.

## Operating it

- **Tenants** page (permission `manage_tenants`): create tenants.
- **Workspaces** page (permission `manage_workspaces`): create workspaces, grant them tenants, and
  manage members.
- **Enrolling agents**: the Add-agent wizard has a **Tenant** picker (shown when more than one tenant
  exists). The enrollment token binds the agent, and therefore all of its telemetry, to that tenant.
- **Switching view**: users in more than one workspace get a workspace switcher in the top bar. It
  sends `X-Workspace-ID` on every request, narrowing their scope to that workspace's tenants.

### New users land in Default

A user created in the UI joins the **Default** workspace automatically, so a new colleague signs in
to the deployment they were hired to watch rather than to an empty product.

They have to land somewhere. Access flows user to workspace to tenant and `ResolveUserScope` fails
closed, so an account with no membership resolves to an empty tenant set: no agents, no events, no
blocklist, and nothing anywhere saying why. Before v2.48.0 that is exactly what happened to every
account created after migration 000049 ran, because 000049 backfilled the users who existed at that
moment and nothing assigned a workspace afterwards.

It went unnoticed for the same reason it is easy to miss now: **admins never hit it.** They carry
`manage_tenants`, which takes the RLS bypass in `withScope` and does not consult membership at all.
Only the analyst and viewer accounts, the ones created for other people, saw the empty deployment.
Migration 000071 repairs any account that is still in that state.

### Moving someone out of Default is two steps, not one

**A user's scope is the UNION of every workspace they belong to.** Adding them to a new workspace
does not take away the old one: the Workspaces page replaces the member list of the workspace you
are editing and touches no other, which is what makes it safe to edit one workspace without
disturbing the rest.

So moving someone to their own tenant means:

1. Add them to the new workspace.
2. **Edit the Default workspace and remove them from its member list.**

Skip the second step and they keep seeing Default's data alongside the new tenant's, which looks
like isolation failing when it is membership doing exactly what it says. This is deliberately not
automatic: silently revoking a membership an administrator did not ask to revoke is a worse
surprise than an explicit second step.

## Deliberately global in v1 (not tenant-scoped)

These are documented trade-offs, each with a forward path:

- **Response actions / bans / the blocklist feed / containment**: a fleet-wide security control
  (block a malicious IP everywhere), not per-tenant telemetry. Stays global.
- **The subscription API (`/api/subscribe/*`) and the ML anomaly bridge (`/api/ml/*`)**, token-authed
  integration feeds that currently span all tenants; anomaly writebacks land in the Default tenant.
  Per-credential tenant scoping is future work.
- **Global configuration** (detection rules, decoders, integrations, playbooks, scoring/notify config,
  CTI, blocklist, IP allowlist) is shared across tenants in v1; a nullable `tenant_id` (NULL = global)
  can be added later without breaking anything.
- **`ticket_comments`** carries no `tenant_id` yet; it is reachable only via a ticket that RLS already
  gates on read. **Ticket creation** stamps the Default tenant (there is no active-tenant context at
  create time); a non-Default tenant creating tickets needs the create path to stamp the active
  workspace's tenant.
