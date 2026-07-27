-- Migration 000049 - Multi-tenancy phase 0: schema + backfill (NO enforcement yet).
--
-- Additive and non-breaking. Every tenant-scoped table gains a `tenant_id` that DEFAULTS to the
-- Default tenant, so existing rows and every current write path keep working unchanged until later
-- phases make the writers tenant-aware. Row-level-security ENFORCEMENT lands separately in 000050
-- (phase 2). The model: agents belong to a tenant (the anchor); telemetry denormalizes tenant_id
-- from its agent; users reach tenants through workspaces (many-to-many).

-- Fixed sentinel IDs so column defaults can reference them and a single-tenant deployment keeps
-- behaving exactly as before (all existing data lands in Default).
--   Default tenant    = 00000000-0000-0000-0000-000000000001
--   Default workspace = 00000000-0000-0000-0000-000000000002

CREATE TABLE IF NOT EXISTS tenants (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL,
    slug       text UNIQUE NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workspaces (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL,
    slug       text UNIQUE NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The many-to-many: a workspace may reach many tenants; a tenant may be shared by many workspaces.
CREATE TABLE IF NOT EXISTS workspace_tenants (
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    tenant_id    uuid NOT NULL REFERENCES tenants(id)    ON DELETE CASCADE,
    PRIMARY KEY (workspace_id, tenant_id)
);

-- Which users belong to which workspace (their access flows workspace -> tenant).
CREATE TABLE IF NOT EXISTS workspace_members (
    workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      uuid NOT NULL REFERENCES users(id)      ON DELETE CASCADE,
    PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_workspace_members_user ON workspace_members (user_id);
CREATE INDEX IF NOT EXISTS idx_workspace_tenants_tenant ON workspace_tenants (tenant_id);

-- Seed Default tenant + workspace, map them, and make every existing user a member so nobody loses
-- access on upgrade.
INSERT INTO tenants (id, name, slug)
    VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default')
    ON CONFLICT (id) DO NOTHING;
INSERT INTO workspaces (id, name, slug)
    VALUES ('00000000-0000-0000-0000-000000000002', 'Default', 'default')
    ON CONFLICT (id) DO NOTHING;
INSERT INTO workspace_tenants (workspace_id, tenant_id)
    VALUES ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001')
    ON CONFLICT DO NOTHING;
INSERT INTO workspace_members (workspace_id, user_id)
    SELECT '00000000-0000-0000-0000-000000000002', id FROM users
    ON CONFLICT DO NOTHING;

-- ── Anchor: agents (and their enroll tokens) belong to a tenant. FK enforced (small tables). ──
ALTER TABLE agents ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL
    DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id);
ALTER TABLE agent_enroll_tokens ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL
    DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id);

-- ── events hypertable: denormalized tenant_id, NO inline FK (TimescaleDB hypertable FK limits);
-- integrity comes from the write path resolving tenant from the agent. A constant DEFAULT makes
-- this a fast metadata-only add on PG11+ (existing rows read the Default without a rewrite). ──
ALTER TABLE events ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL
    DEFAULT '00000000-0000-0000-0000-000000000001';
CREATE INDEX IF NOT EXISTS idx_events_tenant_time ON events (tenant_id, time DESC);

-- ── Agent-keyed and IP-derived tables: denormalized tenant_id. FK skipped here to avoid
-- validation locks on potentially large tables; the value is always a valid tenant (the default,
-- or later derived from the agent). Indexes added where reads will filter by tenant. ──
ALTER TABLE response_actions      ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE containment_actions   ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE fim_snapshots         ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE agent_file_actions    ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE file_restores         ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE agent_os_inventory    ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE agent_packages        ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE agent_vulnerabilities ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE ip_scores             ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE suspicious_ips        ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE slow_scanners         ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE ip_anomaly            ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE tickets               ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

CREATE INDEX IF NOT EXISTS idx_agents_tenant             ON agents (tenant_id);
CREATE INDEX IF NOT EXISTS idx_tickets_tenant            ON tickets (tenant_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_tenant   ON response_actions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_containment_tenant        ON containment_actions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_fim_snapshots_tenant      ON fim_snapshots (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_file_actions_tenant ON agent_file_actions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_os_inv_tenant       ON agent_os_inventory (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_packages_tenant     ON agent_packages (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_vulns_tenant        ON agent_vulnerabilities (tenant_id);
