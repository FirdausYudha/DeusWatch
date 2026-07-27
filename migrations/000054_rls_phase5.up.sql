-- 000054_rls_phase5: extend fail-closed RLS to the tables owned by sibling stores.
--
-- Phase 5. In Phase 2c these were deferred because the enroll and tickets packages queried their own
-- pools without the request scope. They now route through a shared scoped transaction (the tenancy
-- context key), so their tables can join the isolation regime with the same policy as everything else.
--   * agents / agent_enroll_tokens — the agent inventory and enrollment tokens. Gateway paths bypass
--     via the super-admin pool (ConnectSuperadmin); the public /api/enroll handler runs inside a
--     super-admin scope; the session agent routes (list/config/revoke) now filter to the caller's
--     tenants.
--   * tickets — DFIR cases. All ticket routes are session-scoped.
--
-- response_actions / containment_actions (respond package) are intentionally NOT included: bans and
-- the blocklist feed are a fleet-wide security control (block a malicious IP everywhere), not
-- per-tenant telemetry, so they stay global in v1. ticket_comments has no tenant_id yet; it is reached
-- only via a ticket the RLS on `tickets` already gates on read. Both are documented follow-ups.
DO $$
DECLARE t text;
BEGIN
	FOREACH t IN ARRAY ARRAY['agents','agent_enroll_tokens','tickets'] LOOP
		EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
		EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
		EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
		EXECUTE format(
			'CREATE POLICY tenant_isolation ON %I '
			|| 'USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())) '
			|| 'WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))', t);
	END LOOP;
END $$;
