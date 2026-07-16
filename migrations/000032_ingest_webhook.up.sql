-- Migration 000032 - UI-managed token for the inbound raw-log ingest webhook
-- (POST /api/ingest/webhook?token=...). Single-row config; seeded from INGEST_WEBHOOK_TOKEN on
-- first start if set, then managed from the Integrations page. Empty token = webhook disabled (404).
CREATE TABLE IF NOT EXISTS ingest_webhook (
    id         int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    token      text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);
