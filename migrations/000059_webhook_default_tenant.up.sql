-- Migration 000059 - Bind the singleton ingest webhook to a default tenant so payloads land in a
-- deliberate workspace instead of being routed by agent-name lookup (which, when the agent isn't
-- enrolled, falls back to the Default tenant and disappears from any operator's non-Default
-- workspace behind the events RLS view).
--
-- NULL preserves the historical behavior (fall back to agent-name lookup, then Default tenant).
ALTER TABLE ingest_webhook
    ADD COLUMN IF NOT EXISTS default_tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL;
