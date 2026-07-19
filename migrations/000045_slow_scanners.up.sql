-- Migration 000045 - slow-scanner watchlist (low-and-slow reconnaissance across DAYS).
-- The composite score looks at minutes and the suspicious-IP watchlist at ~24h, so a source that
-- probes twice today, nothing tomorrow and five times the day after slips past both — and past
-- every static burst rule, because its whole point is staying under the threshold. This table
-- holds the multi-day view: how many separate days an IP came back, how quietly, over how long.
CREATE TABLE IF NOT EXISTS slow_scanners (
    ip           inet        PRIMARY KEY,
    score        int         NOT NULL DEFAULT 0, -- 0-100
    band         text        NOT NULL DEFAULT 'low',
    active_days  int         NOT NULL DEFAULT 0, -- distinct days seen (the recurrence signal)
    span_days    int         NOT NULL DEFAULT 0, -- days between first and last sighting
    events       int         NOT NULL DEFAULT 0, -- total events in the window
    targets      int         NOT NULL DEFAULT 0, -- distinct URIs/ports probed
    agents       int         NOT NULL DEFAULT 0, -- distinct endpoints touched
    first_seen   timestamptz,
    last_seen    timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_slow_scanners_score ON slow_scanners (score DESC);
