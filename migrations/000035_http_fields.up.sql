-- Migration 000035 - HTTP request context (http.*) for web / WAF events (e.g. ModSecurity).
-- Lets a WAF block surface the blocked URI, target host and status as first-class columns
-- instead of being buried in event_original.
ALTER TABLE events ADD COLUMN IF NOT EXISTS http_method text;
ALTER TABLE events ADD COLUMN IF NOT EXISTS http_uri    text;
ALTER TABLE events ADD COLUMN IF NOT EXISTS http_status integer;
ALTER TABLE events ADD COLUMN IF NOT EXISTS http_host   text;
