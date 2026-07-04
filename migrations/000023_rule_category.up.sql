-- Migration 000023 — rule categories.
--
-- Group detection rules by category (judi, deface, fim, endpoint, agg, general, custom) so
-- the UI can filter the ~1000+ rules by topic. The category mirrors the on-disk folder a
-- builtin was seeded from; user-created rules default to 'custom'. Existing builtins are
-- backfilled from disk on the next api start (rules.SyncBuiltinsFromDir).

ALTER TABLE rules ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_rules_category ON rules (category);
