-- Reverse 000054_rls_phase5: drop the policies and unforce/disable RLS on the sibling-store tables.
DO $$
DECLARE t text;
BEGIN
	FOREACH t IN ARRAY ARRAY['agents','agent_enroll_tokens','tickets'] LOOP
		EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
		EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', t);
		EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
	END LOOP;
END $$;
