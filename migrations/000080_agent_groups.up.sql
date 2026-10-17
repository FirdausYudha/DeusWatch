-- Migration 000080 - agent groups, so a collection policy is set once rather than per agent.
--
-- Config push has worked per agent since the design doc's section 12, and at the scale this was
-- built for that was enough. It is the thing that does not survive growth: 500 endpoints that
-- should all watch the same paths are 500 identical edits, and the 501st is the one nobody did.
-- This is the one capability gap against Wazuh that gets worse the better the product sells.

CREATE TABLE IF NOT EXISTS agent_groups (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    name       text NOT NULL,
    description text NOT NULL DEFAULT '',
    -- The same agent.Config JSON an agent carries, so one shape of config exists rather than two.
    -- Its Version field is ignored here: an agent's effective version is agents.config_rev,
    -- see below.
    config     jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Unique per tenant, not globally: two hospitals both having a "Servers" group is normal.
CREATE UNIQUE INDEX IF NOT EXISTS agent_groups_tenant_name_idx ON agent_groups (tenant_id, lower(name));

ALTER TABLE agents ADD COLUMN IF NOT EXISTS group_id uuid REFERENCES agent_groups(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS agents_group_idx ON agents (group_id) WHERE group_id IS NOT NULL;

-- config_rev is the version the AGENT sees, and it exists because the agent re-applies only when
-- the version it is told is strictly GREATER than the one it is running (cmd/agent/main.go).
--
-- Deriving the effective version from whichever config won would break that. Moving an agent off
-- its own config (version 7) onto a group whose config is at version 2 hands it a LOWER number,
-- and the agent then ignores a change that did happen, silently, forever. A per-agent counter that
-- only ever increases is the only shape that is safe here, so every change that alters an agent's
-- effective config bumps this: its own config, its group assignment, or its group's config.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS config_rev bigint NOT NULL DEFAULT 0;

-- Agents that already carry a pushed config keep their current version as the starting point, so
-- an upgrade does not hand a running agent a number lower than the one it is already on and make
-- its next real change invisible.
UPDATE agents
   SET config_rev = GREATEST(config_rev, coalesce((config->>'version')::bigint, 0))
 WHERE config IS NOT NULL;

-- Tenant isolation, same fail-closed policy every other tenant-scoped table carries (000050).
ALTER TABLE agent_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON agent_groups;
CREATE POLICY tenant_isolation ON agent_groups
    USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))
    WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()));
