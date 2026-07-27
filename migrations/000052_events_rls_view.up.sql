-- 000052_events_rls_view: tenant-isolate the events hypertable with a security-barrier view.
--
-- TimescaleDB 2.17 makes columnar compression and Row-Level Security mutually exclusive
-- ("compression cannot be used on table with row security"; see 000050 header), and events depends on
-- compression for ~90% storage savings. So instead of RLS we put a SECURITY BARRIER VIEW in front of
-- the hypertable that applies the exact same fail-closed filter the RLS policies use.
--
-- Rename the compressed hypertable to events_data (its compression + retention policy jobs reference
-- the hypertable by id, so they follow the rename untouched), then create a view named `events` over
-- it. Every existing `FROM events` read and `INSERT INTO events` / `UPDATE events` write now flows
-- through the view unchanged:
--   * security_barrier = true stops a caller's leaky/volatile function from seeing filtered-out rows
--     before the WHERE is applied.
--   * the view is auto-updatable (single base table, no aggregation), so InsertEvent and SetLLMVerdict
--     keep working; base-table access happens as the view owner while the WHERE is evaluated with the
--     CALLER's GUCs — so isolation still tracks the per-request scope.
--   * WITH CHECK OPTION keeps a write from landing a row outside the writer's scope.
--
-- Reads/writes remain unfiltered for the worker/gateway/system feeds because they run with
-- deuswatch.superadmin = '1' (the OR-clause), exactly as for the RLS tables.
--
-- FOOTGUN: `events` is now a VIEW. Any FUTURE migration that changes the events schema MUST alter
-- `events_data`, then re-run `CREATE OR REPLACE VIEW events AS SELECT * FROM events_data WHERE ...` to
-- surface the change — a plain `SELECT *` view freezes its column list at creation time.

ALTER TABLE events RENAME TO events_data;

CREATE VIEW events WITH (security_barrier = true) AS
	SELECT * FROM events_data
	WHERE current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())
	WITH CHECK OPTION;

-- The restricted request role reaches events only through the view (base-table access is the view
-- owner's job); grant it the DML it needs so scoped reads/writes never hit a "permission denied".
GRANT SELECT, INSERT, UPDATE, DELETE ON events TO deuswatch_app;
