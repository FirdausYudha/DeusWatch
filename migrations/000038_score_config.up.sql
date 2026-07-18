-- Migration 000038 - UI-managed weights for the two IP scorers (composite threat score +
-- suspicious-IP watchlist). Single-row JSON config; empty = the built-in defaults, so existing
-- deployments are unchanged until the operator tunes the weights in Settings.
CREATE TABLE IF NOT EXISTS score_config (
    id         int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    config     jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now()
);
