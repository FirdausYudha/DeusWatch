-- Migration 000061 — ASN enrichment on the events hypertable.
--
-- source_asn_number: 32-bit AS number returned by MaxMind GeoLite2-ASN (int, plenty for the
--   4-byte-AS era). NULL when the enricher can't resolve (missing DB / private RFC1918 IPs /
--   unallocated ranges MaxMind chose not to attribute).
-- source_asn_org: the "organisation" string MaxMind ships alongside the AS number
--   (e.g. "AKAMAI-AS", "PT TELEKOMUNIKASI INDONESIA"). Free-text so it can render directly in
--   the dashboard's Communication Graph without another lookup.
--
-- Nullable, no default — legacy rows stay untouched; going forward the enricher fills them
-- for every event that has a source_ip.
ALTER TABLE events_data
    ADD COLUMN IF NOT EXISTS source_asn_number int,
    ADD COLUMN IF NOT EXISTS source_asn_org    text;

-- FOOTGUN from migration 000052: the `events` VIEW freezes its column list at CREATE-time
-- via SELECT *, so ALTERing events_data alone leaves the new columns invisible to every
-- caller (including InsertEvent's parameterised INSERT — the extra $53/$54 mismatch collapses
-- the whole tenant-scoped transaction). Recreate the view so the ASN columns surface.
CREATE OR REPLACE VIEW events WITH (security_barrier = true) AS
    SELECT * FROM events_data
    WHERE current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())
    WITH CHECK OPTION;
