ALTER TABLE events_data
    DROP COLUMN IF EXISTS source_asn_number,
    DROP COLUMN IF EXISTS source_asn_org;
