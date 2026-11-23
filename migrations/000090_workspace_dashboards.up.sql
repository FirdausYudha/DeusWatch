-- Migration 000090, per-workspace default dashboard layout.
--
-- Companion to 000010 (user_dashboards). A workspace gets ONE shared default layout, edited by a
-- manage_settings user, that every member of that workspace falls back to. A user's personal
-- layout in user_dashboards still wins when present, so the resolution order the API applies is:
-- user override -> workspace default -> coded PANELS default.
--
-- Control-plane table (no tenant_id, no RLS), exactly like user_dashboards: it is keyed by
-- workspace, not by tenant, and reached only through the layout handlers which already authz.
-- deuswatch_app gets SELECT/INSERT/UPDATE/DELETE via the ALTER DEFAULT PRIVILEGES set in 000051.

CREATE TABLE IF NOT EXISTS workspace_dashboards (
    workspace_id uuid PRIMARY KEY REFERENCES workspaces(id) ON DELETE CASCADE,
    layout       jsonb NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
