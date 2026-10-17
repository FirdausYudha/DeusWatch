-- Migration 000082 - configuration-benchmark (CIS) assessment results.
--
-- NOT folded into agent_sca_findings despite the name collision. That table holds software
-- composition analysis: a package, a version and a CVE. This holds configuration hardening: a
-- control, whether the host satisfies it, and how to fix it. Sharing a table because two features
-- were both abbreviated "SCA" would give every column a meaning that depends on which feature
-- wrote the row.
--
-- Current state only, one row per (agent, policy, check). A benchmark answers "is this host
-- hardened today", and an assessment replaces the previous one rather than appending to it. The
-- history that matters, a control that started failing, is already in the events table, where
-- every assessment also lands.

CREATE TABLE IF NOT EXISTS agent_benchmarks (
    agent_name  text NOT NULL,
    tenant_id   uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    policy_id   text NOT NULL,
    policy_name text NOT NULL DEFAULT '',
    check_id    integer NOT NULL,
    title       text NOT NULL DEFAULT '',
    -- passed | failed | not_applicable. not_applicable is a first-class outcome, not a rounding
    -- error: a rule the engine cannot evaluate must never be reported as a failure, because a
    -- failed CIS check sends an operator to change something on a production host.
    result      text NOT NULL,
    -- Why it could not be evaluated. Empty for passed and failed.
    reason      text NOT NULL DEFAULT '',
    remediation text NOT NULL DEFAULT '',
    -- The CIS clause numbers this check satisfies, e.g. {1.1.1.1}. What an auditor asks by.
    cis         text[] NOT NULL DEFAULT '{}',
    assessed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_name, policy_id, check_id)
);

CREATE INDEX IF NOT EXISTS agent_benchmarks_result_idx ON agent_benchmarks (result, policy_id);
CREATE INDEX IF NOT EXISTS agent_benchmarks_agent_idx ON agent_benchmarks (agent_name, assessed_at DESC);

-- Tenant isolation, same fail-closed policy every other tenant-scoped table carries (000050).
ALTER TABLE agent_benchmarks ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_benchmarks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON agent_benchmarks;
CREATE POLICY tenant_isolation ON agent_benchmarks
    USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))
    WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()));
