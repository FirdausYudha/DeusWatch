-- Rollback migrasi 000005.
ALTER TABLE cti_indicators DROP COLUMN IF EXISTS city;
