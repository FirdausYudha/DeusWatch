-- Migration 000034 - persist FIM who-data: the process that changed a file.
-- process.name/pid were dropped on insert before (only user_name was stored); this surfaces the
-- actor for both the DeusWatch agent's audit who-data and the Wazuh syscheck who-data feed.
ALTER TABLE events ADD COLUMN IF NOT EXISTS process_name text;
ALTER TABLE events ADD COLUMN IF NOT EXISTS process_pid  integer;
