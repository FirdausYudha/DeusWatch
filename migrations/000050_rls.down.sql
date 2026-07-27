-- Reverse 000050_rls: drop the isolation policies, unforce/disable RLS, drop the helper functions.
-- After this the tables are visible unscoped again (single-tenant behaviour), so only run it to roll
-- the enforcement flip back — the tenant_id columns from 000049 remain and keep being stamped.
DO $$
DECLARE t text;
BEGIN
	FOREACH t IN ARRAY ARRAY[
		'fim_snapshots','agent_file_actions','file_restores',
		'agent_os_inventory','agent_packages','agent_vulnerabilities',
		'ip_scores','suspicious_ips','slow_scanners','ip_anomaly'
	] LOOP
		EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
		EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', t);
		EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
	END LOOP;
END $$;

DROP FUNCTION IF EXISTS current_is_superadmin();
DROP FUNCTION IF EXISTS current_tenant_ids();
