-- Migration 000036 - pin the AI executive summary to an hour of the day.
-- interval_hours alone drifts (it fires N hours after the previous run, whenever that was), so
-- a "daily" summary slowly walks around the clock. at_hour = 0..23 runs it at that hour in the
-- SERVER's local time; -1 keeps the old drifting-interval behaviour (the default, so existing
-- deployments are unchanged).
ALTER TABLE report_ai_config ADD COLUMN IF NOT EXISTS at_hour smallint NOT NULL DEFAULT -1;
