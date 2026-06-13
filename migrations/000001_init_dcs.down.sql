-- Rollback migrasi 000001 — DCS hypertable events.

SELECT remove_retention_policy('events', if_exists => TRUE);
SELECT remove_compression_policy('events', if_exists => TRUE);
DROP TABLE IF EXISTS events;
