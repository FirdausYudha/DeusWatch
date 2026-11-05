-- Migration 000087 - record when an event was ingested, so MTTD can be measured from real alerts.
--
-- events_data.time is the moment the activity HAPPENED (the agent's clock). It does not say when
-- DeusWatch SAW it. MTTD (mean time to detect) is exactly that gap: for a detection alert, how long
-- after the activity did the alert land. Without an ingestion timestamp the scorecard could only
-- read MTTD from the imported controlled-test log; with it, MTTD is computed from live alerts.
--
-- Added nullable with a DEFAULT for NEW rows only (no volatile default backfill), so this does not
-- rewrite the whole hypertable. Existing rows stay NULL and are simply excluded from MTTD, which is
-- correct: we have no honest ingestion time for events that predate this column.
ALTER TABLE events_data ADD COLUMN IF NOT EXISTS ingested_at timestamptz;
ALTER TABLE events_data ALTER COLUMN ingested_at SET DEFAULT now();

-- FOOTGUN (see migration 000061/000063): the `events` VIEW froze its column list at CREATE-time via
-- SELECT *, so ALTERing events_data alone leaves the new column invisible to callers. Recreate it so
-- ingested_at surfaces in the view the scorecard reads.
CREATE OR REPLACE VIEW events WITH (security_barrier = true) AS
    SELECT * FROM events_data
    WHERE current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())
    WITH CHECK OPTION;
