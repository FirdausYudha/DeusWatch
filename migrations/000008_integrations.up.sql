-- Migration 000008 — integrations registry (firewalls, bouncers, CTI providers).
--
-- Admin-managed connectors added & configured from the UI (Integrations menu).
-- Secret fields inside `config` (API keys, device passwords) are encrypted at rest
-- (see internal/secret) and never returned through the API — they are write-only.

CREATE TABLE IF NOT EXISTS integrations (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    type       text NOT NULL,                    -- mikrotik | crowdsec | nftables_agent | abuseipdb | otx
    name       text NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    config     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_integrations_type ON integrations (type);
