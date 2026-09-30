DROP INDEX IF EXISTS idx_agents_not_deleted;
ALTER TABLE agents DROP COLUMN IF EXISTS deleted_at;
