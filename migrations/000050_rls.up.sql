-- 000050_rls: enforce tenant isolation with fail-closed Row-Level Security.
--
-- Phase 2c of multi-tenancy. Migration 000049 added the tenant_id anchor + denormalized columns;
-- Phase 1/2a/2b stamp tenant_id on write and open a per-request tenant scope. This migration flips
-- on enforcement: from here, Postgres itself filters every row to the caller's tenant set, so a store
-- method that forgets a WHERE clause cannot leak across tenants.
--
-- The scope is carried by two transaction-LOCAL GUCs set by store.WithTenantScope:
--   deuswatch.tenant_ids  — CSV of the caller's accessible tenant UUIDs
--   deuswatch.superadmin  — '1' for trusted system processes (worker/gateway) and the platform
--                           super-admin, who span all tenants (bypass), '0'/unset otherwise.
--
-- Fail-closed: an unscoped path (both GUCs unset) yields an EMPTY tenant array and superadmin=false,
-- so every policy evaluates to false and the query returns zero rows — loud in tests, never a silent
-- cross-tenant leak.

-- current_tenant_ids parses the CSV GUC into uuid[]. Unset or empty → empty array (fail-closed).
CREATE OR REPLACE FUNCTION current_tenant_ids() RETURNS uuid[]
LANGUAGE sql STABLE AS $$
	SELECT CASE
		WHEN coalesce(current_setting('deuswatch.tenant_ids', true), '') = '' THEN ARRAY[]::uuid[]
		ELSE string_to_array(current_setting('deuswatch.tenant_ids', true), ',')::uuid[]
	END
$$;

-- current_is_superadmin reports the bypass GUC. Unset → false (fail-closed).
CREATE OR REPLACE FUNCTION current_is_superadmin() RETURNS boolean
LANGUAGE sql STABLE AS $$
	SELECT coalesce(current_setting('deuswatch.superadmin', true), '0') = '1'
$$;

-- Enable + FORCE RLS and install the isolation policy on each tenant-scoped data table.
-- FORCE is essential: without it RLS is ignored for the table owner, which is exactly the role the
-- API connects as — that would be a silent total leak (store.AssertRLSEnforced guards against it).
-- Only tables reached through the store's s.q(ctx) plumbing are listed here; tables owned by sibling
-- packages without scope plumbing (respond, tickets, enroll) are deferred to a later phase.
--
-- NOTE: the `events` hypertable is intentionally NOT in this list. TimescaleDB 2.17 makes columnar
-- compression and row-level security MUTUALLY EXCLUSIVE ("compression cannot be used on table with
-- row security"), and events relies on compression for ~90% storage savings. Its isolation mechanism
-- is a separate decision (security-barrier view vs. dropping compression) tracked for a follow-up
-- migration; until then events reads stay isolated at the application layer via the scoped store path.
DO $$
DECLARE t text;
BEGIN
	FOREACH t IN ARRAY ARRAY[
		'fim_snapshots','agent_file_actions','file_restores',
		'agent_os_inventory','agent_packages','agent_vulnerabilities',
		'ip_scores','suspicious_ips','slow_scanners','ip_anomaly'
	] LOOP
		EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
		EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
		EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
		EXECUTE format(
			'CREATE POLICY tenant_isolation ON %I '
			|| 'USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())) '
			|| 'WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))', t);
	END LOOP;
END $$;
