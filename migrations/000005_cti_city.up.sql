-- Migration 000005 — add GeoIP city to the CTI cache.
-- The events table has had source_geo_city since 000001; here the CTI cache
-- (cti_indicators) follows so the city is cached alongside country_iso.

ALTER TABLE cti_indicators ADD COLUMN IF NOT EXISTS city text;
