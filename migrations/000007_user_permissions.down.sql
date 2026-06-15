-- Rollback migration 000007.
ALTER TABLE users DROP COLUMN IF EXISTS permissions;
