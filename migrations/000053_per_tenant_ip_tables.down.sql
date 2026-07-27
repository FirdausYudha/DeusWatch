-- Reverse 000053: back to a single-tenant IP key. Only safe if no IP appears under two tenants
-- (true before real multi-tenant data exists); otherwise the ADD PRIMARY KEY (ip) will conflict.
ALTER TABLE ip_scores      DROP CONSTRAINT ip_scores_pkey;
ALTER TABLE ip_scores      ADD  PRIMARY KEY (ip);
ALTER TABLE suspicious_ips DROP CONSTRAINT suspicious_ips_pkey;
ALTER TABLE suspicious_ips ADD  PRIMARY KEY (ip);
ALTER TABLE slow_scanners  DROP CONSTRAINT slow_scanners_pkey;
ALTER TABLE slow_scanners  ADD  PRIMARY KEY (ip);
ALTER TABLE ip_anomaly     DROP CONSTRAINT ip_anomaly_pkey;
ALTER TABLE ip_anomaly     ADD  PRIMARY KEY (ip);
