-- Migration 000072 - hardware asset facts on the agent inventory row (ITIL asset management).
--
-- 000047 collected the SOFTWARE picture (OS release + installed packages) because its purpose was
-- vulnerability matching. An IT team's asset register wants a different set of facts about the
-- same machine: what it is called, who made it, which model, and above all the SERIAL NUMBER,
-- which is what a warranty claim, an audit and a physical stock-take are keyed on. None of that
-- was collected, so the register had to be typed by hand next to a tool that already talks to
-- every endpoint.
--
-- They live on agent_os_inventory rather than a new table: one row per agent already exists, the
-- facts are gathered in the same report, and they change at the same (slow) rate.
--
-- Every column is nullable. Collection is best-effort per field: the DMI serial is root-only on
-- Linux, so an unprivileged agent fills in everything else and leaves that one NULL rather than
-- reporting nothing. Firmware placeholders ("To Be Filled By O.E.M.") are dropped by the agent
-- before they are sent, because a register keyed on serial number would otherwise collapse a
-- whole batch of machines into one asset.

ALTER TABLE agent_os_inventory
    ADD COLUMN IF NOT EXISTS hostname      text,
    ADD COLUMN IF NOT EXISTS manufacturer  text,    -- Dell Inc. | LENOVO | ...
    ADD COLUMN IF NOT EXISTS model         text,    -- OptiPlex 7090 | ThinkCentre M70q
    ADD COLUMN IF NOT EXISTS serial_number text,
    ADD COLUMN IF NOT EXISTS cpu_cores     integer,
    ADD COLUMN IF NOT EXISTS memory_mb     bigint,
    ADD COLUMN IF NOT EXISTS primary_ip    text,
    ADD COLUMN IF NOT EXISTS primary_mac   text;

-- Finding the machine by the number printed on its case is the lookup an asset register exists
-- for, and the one a stock-take does over and over.
CREATE INDEX IF NOT EXISTS agent_os_inventory_serial_idx
    ON agent_os_inventory (serial_number)
    WHERE serial_number IS NOT NULL;
