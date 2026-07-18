-- Migration 000037 - the Suspicious-IP watchlist (low-and-slow reconnaissance).
-- One row per external source IP whose behaviour over a long window looks like scanning/probing
-- even though it never tripped a CTI feed, WAF signature or short-window rule. Refreshed by the
-- worker; see internal/score.ComputeSuspicion.
CREATE TABLE IF NOT EXISTS suspicious_ips (
    ip             inet PRIMARY KEY,
    contacts       int NOT NULL DEFAULT 0, -- total events from this IP in the window
    fanout         int NOT NULL DEFAULT 0, -- distinct targets probed (URIs / ports)
    distinct_hours int NOT NULL DEFAULT 0, -- distinct clock-hours seen (time spread)
    failures       int NOT NULL DEFAULT 0, -- blocked / denied / 4xx / auth-failure
    score          int NOT NULL DEFAULT 0, -- 0..100 behavioral suspicion
    band           text NOT NULL DEFAULT 'low',
    first_seen     timestamptz,
    last_seen      timestamptz,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS suspicious_ips_score_idx ON suspicious_ips (score DESC);
