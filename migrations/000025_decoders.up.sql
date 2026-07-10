-- Migration 000025 - DB-backed custom decoders (data-driven, Wazuh-style).
--
-- A decoder matches a dataset's raw log lines with a Go RE2 regex and maps named capture
-- groups into DCS fields, so a new log source is supported without code. Seeded from the
-- bundled decoders/ on first start (builtin=true), managed from the UI; the gateway loads the
-- enabled set and live-reloads on changes.
CREATE TABLE IF NOT EXISTS decoders (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text    NOT NULL,
    dataset    text    NOT NULL,
    category   text    NOT NULL DEFAULT '',
    action     text    NOT NULL DEFAULT '',
    outcome    text    NOT NULL DEFAULT '',
    level      text    NOT NULL DEFAULT '',
    regex      text    NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    builtin    boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_decoders_enabled ON decoders (enabled);
