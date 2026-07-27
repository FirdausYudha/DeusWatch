-- 000051_app_role: a restricted DB role that actually obeys Row-Level Security.
--
-- The footgun 000050 alone does not close: a PostgreSQL SUPERUSER (and any role with BYPASSRLS)
-- ignores RLS entirely — even FORCE ROW LEVEL SECURITY. The application connects as the bootstrap
-- role `deuswatch`, which is a superuser (it must be, to CREATE EXTENSION timescaledb etc. on a fresh
-- install). If scoped request queries ran as that role they would silently see every tenant's rows.
--
-- Fix: a dedicated NOSUPERUSER NOBYPASSRLS role, `deuswatch_app`, that RLS DOES constrain. It is
-- NOLOGIN and reached only via `SET LOCAL ROLE deuswatch_app` inside store.WithTenantScope's
-- non-super-admin request transactions (transaction-local, auto-reverting on commit) — so migrations,
-- the worker, the gateway, seeding, and super-admin scopes keep the privileged role, while ordinary
-- scoped reads drop to a role the database will filter. It needs plain DML on every table the request
-- paths touch (RLS, not permissions, does the isolation); missing a grant would surface as a loud
-- "permission denied", never a silent leak.
DO $$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deuswatch_app') THEN
		CREATE ROLE deuswatch_app NOSUPERUSER NOBYPASSRLS NOLOGIN;
	ELSE
		ALTER ROLE deuswatch_app NOSUPERUSER NOBYPASSRLS NOLOGIN;
	END IF;
END $$;

GRANT USAGE ON SCHEMA public TO deuswatch_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO deuswatch_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO deuswatch_app;

-- Future tables/sequences created by the migration role inherit the same grants automatically.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
	GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO deuswatch_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
	GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO deuswatch_app;
