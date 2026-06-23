-- Migration 000011 — DB-backed detection rules (Wazuh-style management).
--
-- Rules are Sigma YAML, classified as single-event or aggregation. They are seeded
-- from the bundled rules/ on first start (builtin=true) and can be added/edited/disabled/
-- deleted from the UI; the worker loads the enabled set and live-reloads on changes.

CREATE TABLE IF NOT EXISTS rules (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text    NOT NULL,
    kind       text    NOT NULL,            -- single | aggregation
    yaml       text    NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    builtin    boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules (enabled);
