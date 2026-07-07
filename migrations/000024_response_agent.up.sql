-- Migration 000024 - record which agent's alert triggered a response action, so the Response
-- view can show the affected agent/host (not just the offending IP). Populated by the response
-- engine from the triggering alert's agent identity (cert CN).
ALTER TABLE response_actions ADD COLUMN IF NOT EXISTS agent_id text;
