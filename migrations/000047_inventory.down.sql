-- Revert 000047 - software inventory.
DROP INDEX IF EXISTS idx_agent_packages_source;
DROP INDEX IF EXISTS idx_agent_packages_agent;
DROP TABLE IF EXISTS agent_packages;
DROP TABLE IF EXISTS agent_os_inventory;
