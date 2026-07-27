-- Reverse 000052_events_rls_view: drop the view and rename the hypertable back to events.
-- Grants that lived on the view disappear with it; the events_data grants (inherited from the
-- original events table) follow the rename back onto events.
DROP VIEW IF EXISTS events;
ALTER TABLE events_data RENAME TO events;
