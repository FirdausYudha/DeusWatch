-- Reverse 000051_app_role: revoke grants and drop the restricted role.
-- Roles are cluster-global, so guard the drop. Reversing the default privileges first prevents
-- "role cannot be dropped because some objects depend on it".
ALTER DEFAULT PRIVILEGES IN SCHEMA public
	REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM deuswatch_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
	REVOKE USAGE, SELECT, UPDATE ON SEQUENCES FROM deuswatch_app;

DO $$
BEGIN
	IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'deuswatch_app') THEN
		EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM deuswatch_app';
		EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM deuswatch_app';
		EXECUTE 'REVOKE USAGE ON SCHEMA public FROM deuswatch_app';
		EXECUTE 'DROP ROLE deuswatch_app';
	END IF;
END $$;
