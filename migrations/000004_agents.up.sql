-- Migration 000004 — agent registration & enrollment tokens (design doc sections 4 & 12).

-- Registered agents. Each agent has a UNIQUE client certificate (CN = name); revoked
-- = true makes the gateway reject its connection. The config column is for config-push.
CREATE TABLE IF NOT EXISTS agents (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text UNIQUE NOT NULL,
    os           text,
    cert_serial  text,
    enrolled_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    config       jsonb,
    revoked      boolean NOT NULL DEFAULT false
);

-- Single-use enrollment tokens with a short lifetime. Stored as a HASH.
CREATE TABLE IF NOT EXISTS agent_enroll_tokens (
    token_hash    text PRIMARY KEY,
    created_by    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    used_by_agent uuid REFERENCES agents(id) ON DELETE SET NULL
);
