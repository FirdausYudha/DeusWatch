-- Revert 000049 - Multi-tenancy phase 0.
-- Drop the denormalized tenant_id columns, then the membership/mapping tables, then tenants.

ALTER TABLE tickets               DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE ip_anomaly            DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE slow_scanners         DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE suspicious_ips        DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE ip_scores             DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE agent_vulnerabilities DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE agent_packages        DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE agent_os_inventory    DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE file_restores         DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE agent_file_actions    DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE fim_snapshots         DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE containment_actions   DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE response_actions      DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS idx_events_tenant_time;
ALTER TABLE events                DROP COLUMN IF EXISTS tenant_id;

ALTER TABLE agent_enroll_tokens   DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE agents                DROP COLUMN IF EXISTS tenant_id;

DROP TABLE IF EXISTS workspace_members;
DROP TABLE IF EXISTS workspace_tenants;
DROP TABLE IF EXISTS workspaces;
DROP TABLE IF EXISTS tenants;
