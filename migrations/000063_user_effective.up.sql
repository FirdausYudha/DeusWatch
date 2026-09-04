-- Migration 000063, the effective user behind a change, so "via sudo" is visible.
--
-- Linux who-data reads two accounts from every audit record: auid, the account the human
-- authenticated as (it survives sudo/su unchanged), and uid, the account the process actually
-- ran as. Until now the agent collapsed them into one value, which threw away the only evidence
-- that privilege escalation was involved: `auid=1000 uid=0` was reported as plain "1000", making
-- a change made with full root privilege look like an ordinary user edit.
--
-- user_name keeps the LOGIN account (the person to hold responsible); user_effective carries the
-- account the process ran as, and is NULL when who-data is off or the two are the same.
ALTER TABLE events_data
    ADD COLUMN IF NOT EXISTS user_effective text;

-- FOOTGUN, as documented in migration 000061: the `events` VIEW froze its column list at
-- CREATE-time via SELECT *, so ALTERing events_data alone leaves the new column invisible to
-- every caller, including InsertEvent's parameterised INSERT, where the extra placeholder
-- collapses the whole tenant-scoped transaction. Recreate the view so the column surfaces.
CREATE OR REPLACE VIEW events WITH (security_barrier = true) AS
    SELECT * FROM events_data
    WHERE current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())
    WITH CHECK OPTION;
