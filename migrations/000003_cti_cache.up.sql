-- Migration 000003 — TTL-based CTI cache (design doc section 3).
--
-- CTI lookup results are stored as ROWS in Postgres with a TTL column (expires_at),
-- NOT an in-memory cache. The worker checks this table before calling external APIs;
-- the PRIMARY KEY on ip + UPSERT (ON CONFLICT) resolves cross-worker races
-- deterministically — there is never a "cache collision".

CREATE TABLE IF NOT EXISTS cti_indicators (
    ip               inet        PRIMARY KEY,
    abuse_confidence smallint    NOT NULL DEFAULT 0,   -- 0..100 (AbuseIPDB)
    otx_pulse_count  integer     NOT NULL DEFAULT 0,   -- number of OTX pulses
    country_iso      text,
    feed_name        text,
    checked_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL              -- TTL: row is stale after this
);

CREATE INDEX IF NOT EXISTS idx_cti_expires ON cti_indicators (expires_at);
