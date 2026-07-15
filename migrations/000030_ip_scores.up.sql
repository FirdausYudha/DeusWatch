-- Migration 000030 - composite threat scoring per source IP (Multi-Source Event
-- Correlation). A periodic scorer accumulates signals over a window (fired_times +
-- AbuseIPDB + OTX + worst severity) into one 0-100 score + band per source IP; the
-- dashboard shows it as a per-row risk indicator and it can drive a "scenario ban".
CREATE TABLE IF NOT EXISTS ip_scores (
    ip          inet PRIMARY KEY,
    score       int         NOT NULL,
    band        text        NOT NULL,
    fired_times int         NOT NULL DEFAULT 0,
    abuse       int         NOT NULL DEFAULT 0,
    otx         int         NOT NULL DEFAULT 0,
    max_sev     int         NOT NULL DEFAULT 0,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ip_scores_score ON ip_scores (score DESC);
