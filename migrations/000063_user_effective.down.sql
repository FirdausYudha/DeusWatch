ALTER TABLE events_data DROP COLUMN IF EXISTS user_effective;

-- Recreate the view so its frozen column list matches the reverted table.
CREATE OR REPLACE VIEW events WITH (security_barrier = true) AS
    SELECT * FROM events_data
    WHERE current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())
    WITH CHECK OPTION;
