-- Migration 000068: the AI assistant's configurable persona (ADR 0003, phase 4).
--
-- One row, like report_ai_config. The persona steers tone, language and, more importantly, the
-- assistant's honesty about its own limits, so operators need to edit it without a redeploy.
--
-- An empty string means "use the built-in default", which is also what the row looks like on a
-- fresh install, so the feature has no migration-time behaviour change at all.
CREATE TABLE IF NOT EXISTS assistant_config (
    id      smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    persona text NOT NULL DEFAULT ''
);

INSERT INTO assistant_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
