-- 000053_per_tenant_ip_tables: make the IP-derived scorer tables per-tenant.
--
-- Phase 3 of multi-tenancy. The worker recomputes these tables with GROUP BY (tenant_id, source_ip);
-- the primary key must match so one IP seen in two tenants keeps two INDEPENDENT scores, and the
-- cross-agent fan-out signal (count(DISTINCT agent_id)) is counted within a tenant instead of blending
-- one tenant's agents into another's score. All existing rows are in the Default tenant, so
-- (tenant_id, ip) is unique over them and this key swap is non-destructive.
ALTER TABLE ip_scores      DROP CONSTRAINT ip_scores_pkey;
ALTER TABLE ip_scores      ADD  PRIMARY KEY (tenant_id, ip);
ALTER TABLE suspicious_ips DROP CONSTRAINT suspicious_ips_pkey;
ALTER TABLE suspicious_ips ADD  PRIMARY KEY (tenant_id, ip);
ALTER TABLE slow_scanners  DROP CONSTRAINT slow_scanners_pkey;
ALTER TABLE slow_scanners  ADD  PRIMARY KEY (tenant_id, ip);
ALTER TABLE ip_anomaly     DROP CONSTRAINT ip_anomaly_pkey;
ALTER TABLE ip_anomaly     ADD  PRIMARY KEY (tenant_id, ip);
