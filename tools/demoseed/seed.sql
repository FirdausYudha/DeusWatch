-- Dummy data for a visual walkthrough of the DeusWatch dashboard.
-- Everything is generated so the widgets are internally consistent: the severity mix, the LLM
-- verdict donut, the country map and the risky-IP scores all describe the SAME events.
--
-- All rows are tagged event_dataset LIKE 'demo%' so they can be removed in one statement.

BEGIN;

DELETE FROM events WHERE event_dataset LIKE 'demo%';

-- A cast of source IPs with a country and a "character" (how nasty they are).
CREATE TEMP TABLE demo_actors (ip inet, iso text, city text, nastiness int) ON COMMIT DROP;
INSERT INTO demo_actors VALUES
  ('185.243.115.84','RU','Moscow',        95),
  ('45.155.205.233','RU','Saint Petersburg',88),
  ('103.85.24.19','CN','Shanghai',        82),
  ('61.177.173.12','CN','Nanjing',        78),
  ('194.26.29.171','NL','Amsterdam',      70),
  ('141.98.10.62','LT','Vilnius',         65),
  ('92.63.197.44','RU','Kazan',           60),
  ('167.94.138.20','US','Ann Arbor',      35),
  ('20.51.183.99','US','Des Moines',      25),
  ('36.94.112.7','ID','Jakarta',          20),
  ('114.125.60.41','ID','Surabaya',       15),
  ('202.80.215.6','SG','Singapore',       10);

-- The endpoints reporting in (drives cross-agent fan-out scoring).
CREATE TEMP TABLE demo_agents (agent text) ON COMMIT DROP;
INSERT INTO demo_agents VALUES ('web01'),('web02'),('db01'),('mail01'),('gw01'),('app01');

-- ── Bulk traffic: 14 days of events, weighted towards recent ──────────────────
INSERT INTO events (
  time, event_category, event_action, event_outcome, event_severity, event_dataset,
  event_original, source_ip, source_port, source_geo_country_iso, source_geo_city,
  destination_port, host_name, agent_id, user_name, network_transport,
  rule_id, rule_name, threat_technique_id, threat_technique_name, threat_tactic_name,
  dw_enrichment_status, dw_enrichment_abuse_confidence, dw_enrichment_otx_pulse_count,
  dw_label, http_method, http_uri, http_status
)
SELECT
  -- Each actor runs a short CAMPAIGN rather than trickling for a fortnight: it is active on a
  -- couple of adjacent days, starting on a day derived from its address. Different actors start
  -- on different days, so the timeline is populated across the whole window while no loud actor
  -- looks like a patient multi-day scanner. That keeps the slow-scanner watchlist meaningful —
  -- it must surface the ONE stealthy source, not everybody.
  now()
    - (((('x' || substr(md5(host(a.ip)), 1, 4))::bit(16)::int % 12) + (g % 2)) || ' days')::interval
    - (random() * interval '10 hours')                                      AS time,
  c.category,
  c.action,
  CASE WHEN random() < 0.75 THEN 'failure' ELSE 'success' END,
  -- Nastier actors skew to higher severity. 0=info .. 4=critical
  LEAST(4, GREATEST(0, (a.nastiness / 25.0 + (random() * 2 - 1))::int))     AS event_severity,
  'demo_' || c.dataset,
  c.original,
  a.ip,
  32000 + (random() * 30000)::int,
  a.iso,
  a.city,
  c.dport,
  ag.agent || '.deuswatch.local',
  ag.agent,
  c.username,
  'tcp',
  c.rule_id,
  c.rule_name,
  c.tech_id,
  c.tech_name,
  c.tactic,
  'enriched',
  GREATEST(0, LEAST(100, a.nastiness + (random() * 20 - 10)::int)),
  (a.nastiness / 20)::int,
  -- Only the serious ones are labelled alerts; the rest are plain telemetry.
  CASE WHEN a.nastiness > 55 AND random() < 0.45 THEN c.rule_name ELSE NULL END,
  c.method, c.uri, c.status
FROM demo_actors a
CROSS JOIN demo_agents ag
CROSS JOIN LATERAL (
  SELECT * FROM (VALUES
    ('authentication','logon_failed','sshd', 22,'root',
     'Failed password for root from '||host(a.ip)||' port 47122 ssh2',
     'SSH-BRUTE-001','SSH brute-force attempt','T1110.001','Password Guessing','Credential Access',
     NULL::text, NULL::text, NULL::int),
    ('web','http_request','nginx', 443,'-',
     host(a.ip)||' - - [GET] /wp-login.php HTTP/1.1 401',
     'WEB-LOGIN-002','Repeated web login failures','T1110','Brute Force','Credential Access',
     'POST','/wp-login.php',401),
    ('web','http_request','nginx', 443,'-',
     host(a.ip)||' - - [GET] /.env HTTP/1.1 404',
     'WEB-SCAN-004','Sensitive file probing','T1595.003','Wordlist Scanning','Reconnaissance',
     'GET','/.env',404),
    ('network','connection_attempt','firewall', 3389,'-',
     '[UFW BLOCK] SRC='||host(a.ip)||' DPT=3389 PROTO=TCP',
     'NET-RDP-003','RDP exposure probe','T1021.001','Remote Desktop Protocol','Lateral Movement',
     NULL,NULL,NULL),
    ('intrusion_detection','network_ids_alert','suricata', 80,'-',
     'ET SCAN Suspicious inbound to '||host(a.ip),
     'IDS-SCAN-005','IDS signature match','T1046','Network Service Discovery','Discovery',
     NULL,NULL,NULL)
  ) AS v(category,action,dataset,dport,username,original,rule_id,rule_name,tech_id,tech_name,tactic,method,uri,status)
) c
-- More events for nastier actors, and more on the busier agents.
CROSS JOIN generate_series(1, GREATEST(2, (a.nastiness / 8)::int)) g;

-- ── LLM verdicts (the donut) ─────────────────────────────────────────────────
-- Only analyzed alerts get a verdict, and the verdict tracks severity so the donut agrees with
-- the severity chart rather than contradicting it.
UPDATE events SET
  dw_llm_verdict = CASE
    WHEN event_severity >= 4 THEN 'malicious'
    WHEN event_severity = 3  THEN (ARRAY['malicious','suspicious'])[1 + (random() * 1.4)::int]
    WHEN event_severity = 2  THEN (ARRAY['suspicious','needs_review'])[1 + (random() * 1.4)::int]
    ELSE (ARRAY['needs_review','benign'])[1 + (random() * 1.4)::int]
  END,
  dw_llm_summary = 'Automated triage: correlated with '
                   || (2 + (random() * 8)::int) || ' related events from the same source.',
  dw_llm_analyzed_at = time + interval '30 seconds'
WHERE event_dataset LIKE 'demo%' AND dw_label IS NOT NULL;

-- ── A slow scanner: low volume, many separate days (invisible to burst rules) ─
INSERT INTO events (time, event_category, event_action, event_outcome, event_severity,
                    event_dataset, event_original, source_ip, source_geo_country_iso,
                    source_geo_city, agent_id, http_uri, rule_id, rule_name)
SELECT
  now() - (d || ' days')::interval + (random() * interval '6 hours'),
  'web','http_request','failure', 1, 'demo_nginx',
  '203.0.113.77 - - [GET] /admin'||d||'/ HTTP/1.1 404',
  '203.0.113.77','SG','Singapore',
  (ARRAY['web01','web02','gw01'])[1 + (random() * 2)::int],
  '/admin'||d||'/', 'WEB-SCAN-004','Sensitive file probing'
FROM generate_series(1, 13, 2) d,           -- days 1,3,5,7,9,11,13 - seven separate days
     generate_series(1, 2) n;               -- only 2 hits per day

COMMIT;

SELECT 'events seeded: ' || count(*) FROM events WHERE event_dataset LIKE 'demo%';

-- ── Recent activity (last 24h) ───────────────────────────────────────────────
-- The dashboard opens on a 24-hour window by default, so without this the default view would be
-- almost empty while the 14-day view looked busy. This gives "today" its own campaign.
BEGIN;

INSERT INTO events (
  time, event_category, event_action, event_outcome, event_severity, event_dataset,
  event_original, source_ip, source_port, source_geo_country_iso, source_geo_city,
  destination_port, host_name, agent_id, user_name, network_transport,
  rule_id, rule_name, threat_technique_id, threat_technique_name, threat_tactic_name,
  dw_enrichment_status, dw_enrichment_abuse_confidence, dw_enrichment_otx_pulse_count,
  dw_label, http_method, http_uri, http_status
)
SELECT
  now() - (random() * interval '23 hours'),
  c.category, c.action,
  CASE WHEN random() < 0.75 THEN 'failure' ELSE 'success' END,
  LEAST(4, GREATEST(0, (a.nastiness / 25.0 + (random() * 2 - 1))::int)),
  'demo_' || c.dataset, c.original,
  a.ip, 32000 + (random() * 30000)::int, a.iso, a.city, c.dport,
  ag.agent || '.deuswatch.local', ag.agent, c.username, 'tcp',
  c.rule_id, c.rule_name, c.tech_id, c.tech_name, c.tactic,
  'enriched',
  GREATEST(0, LEAST(100, a.nastiness + (random() * 20 - 10)::int)),
  (a.nastiness / 20)::int,
  CASE WHEN a.nastiness > 55 AND random() < 0.45 THEN c.rule_name ELSE NULL END,
  c.method, c.uri, c.status
FROM (VALUES
    ('185.243.115.84'::inet,'RU','Moscow',95),
    ('45.155.205.233'::inet,'RU','Saint Petersburg',88),
    ('103.85.24.19'::inet,'CN','Shanghai',82),
    ('194.26.29.171'::inet,'NL','Amsterdam',70),
    ('167.94.138.20'::inet,'US','Ann Arbor',35),
    ('36.94.112.7'::inet,'ID','Jakarta',20)
  ) AS a(ip,iso,city,nastiness)
CROSS JOIN (VALUES ('web01'),('web02'),('db01'),('mail01'),('gw01')) AS ag(agent)
CROSS JOIN LATERAL (
  SELECT * FROM (VALUES
    ('authentication','logon_failed','sshd',22,'root',
     'Failed password for root from '||host(a.ip)||' port 51884 ssh2',
     'SSH-BRUTE-001','SSH brute-force attempt','T1110.001','Password Guessing','Credential Access',
     NULL::text,NULL::text,NULL::int),
    ('web','http_request','nginx',443,'-',
     host(a.ip)||' - - [POST] /wp-login.php HTTP/1.1 401',
     'WEB-LOGIN-002','Repeated web login failures','T1110','Brute Force','Credential Access',
     'POST','/wp-login.php',401),
    ('network','connection_attempt','firewall',3389,'-',
     '[UFW BLOCK] SRC='||host(a.ip)||' DPT=3389 PROTO=TCP',
     'NET-RDP-003','RDP exposure probe','T1021.001','Remote Desktop Protocol','Lateral Movement',
     NULL,NULL,NULL)
  ) AS v(category,action,dataset,dport,username,original,rule_id,rule_name,tech_id,tech_name,tactic,method,uri,status)
) c
CROSS JOIN generate_series(1, GREATEST(2, (a.nastiness / 12)::int)) g;

-- Verdicts for the new alerts (keeps the donut agreeing with the severity chart).
UPDATE events SET
  dw_llm_verdict = CASE
    WHEN event_severity >= 4 THEN 'malicious'
    WHEN event_severity = 3  THEN (ARRAY['malicious','suspicious'])[1 + (random() * 1.4)::int]
    WHEN event_severity = 2  THEN (ARRAY['suspicious','needs_review'])[1 + (random() * 1.4)::int]
    ELSE (ARRAY['needs_review','benign'])[1 + (random() * 1.4)::int]
  END,
  dw_llm_summary = 'Automated triage: correlated with '
                   || (2 + (random() * 8)::int) || ' related events from the same source.',
  dw_llm_analyzed_at = time + interval '30 seconds'
WHERE event_dataset LIKE 'demo%' AND dw_label IS NOT NULL AND dw_llm_verdict IS NULL;

COMMIT;

SELECT 'total demo events: ' || count(*) FROM events WHERE event_dataset LIKE 'demo%';
SELECT 'in last 24h: ' || count(*) FROM events WHERE event_dataset LIKE 'demo%' AND time > now() - interval '24 hours';
