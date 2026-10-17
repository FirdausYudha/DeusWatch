-- Migration 000079 - the bit that lets the worker know what it has already announced.
--
-- env_sensors.alerting records whether a sensor is in breach RIGHT NOW, written by the ingest
-- endpoint as each reading arrives. The worker is what turns that into an alert, and it needs to
-- know which transitions it has already announced: without this column the only alternative is
-- holding that state in memory, and then a worker restart re-announces every sensor currently out
-- of range at once.
--
-- A separate migration rather than an edit to 000078, which is unreleased and probably unapplied:
-- "probably" is not good enough, because editing a migration that HAS run leaves the column
-- missing with no sign of it until the feature fails at runtime.

ALTER TABLE env_sensors
    ADD COLUMN IF NOT EXISTS notified boolean NOT NULL DEFAULT false;

-- The sweep asks for exactly this, every minute.
CREATE INDEX IF NOT EXISTS env_sensors_pending_idx
    ON env_sensors (enabled)
    WHERE alerting <> notified;
