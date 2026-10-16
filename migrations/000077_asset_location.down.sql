-- Reversing this drops data no agent can regenerate: a location and an asset tag were typed by a
-- person who walked to the machine. The columns go, since that is what a down migration means, but
-- an operator reading this should know the cost is a stock-take, not a re-sync.
DROP INDEX IF EXISTS agent_os_inventory_location_idx;

ALTER TABLE agent_os_inventory
    DROP COLUMN IF EXISTS location,
    DROP COLUMN IF EXISTS asset_tag,
    DROP COLUMN IF EXISTS asset_notes,
    DROP COLUMN IF EXISTS asset_updated_at,
    DROP COLUMN IF EXISTS asset_updated_by;
