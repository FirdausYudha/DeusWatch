DROP INDEX IF EXISTS env_sensors_pending_idx;
ALTER TABLE env_sensors DROP COLUMN IF EXISTS notified;
