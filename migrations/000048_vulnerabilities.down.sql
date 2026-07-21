-- Revert 000048 - Vulnerability Assessment phase 2.
DROP INDEX IF EXISTS idx_agent_vulns_severity;
DROP INDEX IF EXISTS idx_agent_vulns_agent;
DROP TABLE IF EXISTS agent_vulnerabilities;
DROP INDEX IF EXISTS idx_advisories_lookup;
DROP TABLE IF EXISTS advisories;
