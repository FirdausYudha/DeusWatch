-- Migration 000083 - centrally managed CIS benchmark policies.
--
-- v2.61.0 shipped benchmarks reading policy files placed on each endpoint, and refused to
-- distribute them from the manager because a policy's `c:` rules are shell commands run as the
-- agent's user, usually root. That reasoning was inconsistent with what the agent already does:
-- performSelfUpdate downloads a binary from the manager and replaces the RUNNING EXECUTABLE with
-- no signature check, pinning TLS to the manager's CA, which authenticates the manager and not
-- the content. A compromised manager therefore already has root code execution on every agent.
--
-- So central distribution adds no new trust boundary, and the file-per-host-forever cost was
-- being paid to guard a door while a wider one stood open. Signing both the binary and the
-- policies is the real fix and is tracked separately; it is not a reason to withhold this.
--
-- An endpoint can still opt out with SCA_ALLOW_PUSHED=0, and a policy placed locally still wins
-- over a pushed one of the same id, so the endpoint administrator keeps the final say.

CREATE TABLE IF NOT EXISTS sca_policies (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    -- policy_id is the `policy.id` inside the YAML, e.g. cis_debian10. Unique per tenant so an
    -- operator cannot have two copies of the same benchmark disagreeing with each other.
    policy_id   text NOT NULL,
    name        text NOT NULL DEFAULT '',
    -- The policy YAML, stored verbatim. Parsed and validated at UPLOAD, so a malformed benchmark
    -- is rejected by one person at one keyboard rather than silently skipped on 500 endpoints.
    yaml        text NOT NULL,
    check_count integer NOT NULL DEFAULT 0,
    enabled     boolean NOT NULL DEFAULT true,
    -- rev is bumped on every change so an agent can tell its cache is stale without diffing the
    -- YAML. Monotonic per policy for the same reason agents.config_rev is: a number that can go
    -- down is a change that never gets applied.
    rev         bigint NOT NULL DEFAULT 1,
    uploaded_by text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS sca_policies_tenant_policy_idx ON sca_policies (tenant_id, policy_id);
CREATE INDEX IF NOT EXISTS sca_policies_enabled_idx ON sca_policies (enabled);

-- Tenant isolation, same fail-closed policy every other tenant-scoped table carries (000050).
ALTER TABLE sca_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE sca_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON sca_policies;
CREATE POLICY tenant_isolation ON sca_policies
    USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))
    WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()));
