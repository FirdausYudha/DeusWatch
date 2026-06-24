-- Migration 000012 — configurable progressive-ban policy (single row).
--
-- durations[]: ban length (seconds) for the 1st, 2nd, … offense (the escalation ladder,
-- e.g. 600,1800,3600 = 10m,30m,1h). permanent: an offense beyond the ladder = permanent.
-- window_secs: only count prior offenses within this window (0 = all history).

CREATE TABLE IF NOT EXISTS ban_policy (
    id          int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    durations   int[]   NOT NULL,
    permanent   boolean NOT NULL DEFAULT true,
    window_secs int     NOT NULL DEFAULT 0,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
