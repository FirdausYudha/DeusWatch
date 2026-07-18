-- Migration 000040 - the subscription API (a sellable "rich-log" product).
-- Each row is an external subscriber that may PULL enriched events / threat indicators over a
-- token-authed API. Only the SHA-256 of the API key is stored (the plaintext is shown once at
-- creation, exactly like a personal access token); auth hashes the presented key and looks it up.
-- last_used_at / request_count give a usage trail for billing and revocation decisions.
CREATE TABLE IF NOT EXISTS subscriptions (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text        NOT NULL,
    token_hash    text        NOT NULL UNIQUE,       -- sha256 hex of the API key
    scopes        text[]      NOT NULL DEFAULT '{events}', -- events | indicators
    min_severity  smallint    NOT NULL DEFAULT 0,    -- only serve events at/above this severity
    enabled       boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    request_count bigint      NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_subscriptions_token_hash ON subscriptions (token_hash);
