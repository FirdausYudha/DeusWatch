DROP INDEX IF EXISTS idx_rules_category;
ALTER TABLE rules DROP COLUMN IF EXISTS category;
