-- Migration 000027 - agent self-monitoring (design doc section 13).
-- status is maintained by the worker's health checker:
--   unknown (enrolled, never seen) -> online -> degraded (heartbeat ok but the
--   agent reports a problem, e.g. buffer piling up) -> disconnected (3x heartbeats
--   missed - raises a high-severity selfhealth alert) -> stale (offline > 24h).
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS status          text    NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS health_degraded boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS health_detail   text    NOT NULL DEFAULT '';
