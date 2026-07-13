ALTER TABLE agents
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS health_degraded,
    DROP COLUMN IF EXISTS health_detail;
