-- Migration 000077 - the operator-owned half of the asset register.
--
-- 000072 added the facts a machine can report about itself: manufacturer, model, serial number.
-- The field engineer asked for one more, and it is the one no agent can answer:
--
--   "Merek komputer juga bisa. Jadi lokasinya nanti ketahuan."
--
-- Where the machine physically is. A hospital's register is used to walk to a device: which ward,
-- which nurse station, which floor. No API knows that, so it is typed once by the person who put
-- the machine there.
--
-- That makes these columns different in kind from every other column on this table. Everything
-- else is overwritten by the agent's next report; these must survive it. The upsert in
-- ReplaceInventory never names them, so an agent report cannot touch them: the protection is the
-- absence, which is easy to undo by accident, so it is stated here as well.
--
-- asset_tag is the organisation's own inventory number, the sticker on the case. It is separate
-- from serial_number because they are different identifiers owned by different parties, and a
-- stock-take reconciles one against the other.

ALTER TABLE agent_os_inventory
    ADD COLUMN IF NOT EXISTS location    text,
    ADD COLUMN IF NOT EXISTS asset_tag   text,
    ADD COLUMN IF NOT EXISTS asset_notes text,
    ADD COLUMN IF NOT EXISTS asset_updated_at timestamptz,
    ADD COLUMN IF NOT EXISTS asset_updated_by text;

-- "Everything in Ward 3" is the question a register is asked while someone is standing in Ward 3.
CREATE INDEX IF NOT EXISTS agent_os_inventory_location_idx
    ON agent_os_inventory (location)
    WHERE location IS NOT NULL;
