-- Migration 000060 — self-update flow for the fleet.
--
-- agent_version: what the agent last reported on heartbeat (X-ish header repurposed as JSON
-- body field). Lets the UI show "agent 2.11.0 · manager 2.12.0" and gate the Update button.
-- update_requested_at: operator asked for an in-place upgrade. Cleared automatically once the
-- agent's next heartbeat reports the manager's current version (see cmd/api/main.go's version
-- comparison in the heartbeat handler).
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS agent_version        text,
    ADD COLUMN IF NOT EXISTS update_requested_at  timestamptz;
