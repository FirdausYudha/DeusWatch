DROP TABLE IF EXISTS scan_status;
ALTER TABLE agent_sca_findings     DROP COLUMN IF EXISTS cvss;
ALTER TABLE agent_vulnerabilities  DROP COLUMN IF EXISTS cvss;
