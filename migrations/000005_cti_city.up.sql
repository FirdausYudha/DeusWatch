-- Migrasi 000005 — tambah kota GeoIP ke cache CTI.
-- Tabel events sudah punya source_geo_city sejak 000001; di sini cache CTI
-- (cti_indicators) menyusul agar kota ikut di-cache bersama country_iso.

ALTER TABLE cti_indicators ADD COLUMN IF NOT EXISTS city text;
