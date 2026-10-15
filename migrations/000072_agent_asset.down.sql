-- Reverse 000072: drop the hardware asset columns and their index.
--
-- Safe to reverse: the data is re-collected from the endpoint on the agent's next inventory
-- report, so nothing is lost that the fleet cannot tell us again.

DROP INDEX IF EXISTS agent_os_inventory_serial_idx;

ALTER TABLE agent_os_inventory
    DROP COLUMN IF EXISTS hostname,
    DROP COLUMN IF EXISTS manufacturer,
    DROP COLUMN IF EXISTS model,
    DROP COLUMN IF EXISTS serial_number,
    DROP COLUMN IF EXISTS cpu_cores,
    DROP COLUMN IF EXISTS memory_mb,
    DROP COLUMN IF EXISTS primary_ip,
    DROP COLUMN IF EXISTS primary_mac;
