-- Migration 000028 - remediation playbooks (design doc section 9).
--
-- A playbook maps a detection label (deuswatch.label, e.g. "bruteforce",
-- "credential_access") to a static list of remediation steps. The worker stamps the
-- matching playbook onto every fired alert (deuswatch.remediation.*): deterministic,
-- <1ms, no cost, fully auditable. Seeded from the bundled rules/playbooks/ on first
-- start (builtin=true) and managed from the UI; the worker live-reloads the enabled set.
CREATE TABLE IF NOT EXISTS playbooks (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    label      text    NOT NULL UNIQUE,
    name       text    NOT NULL,
    steps      text[]  NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    builtin    boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON playbooks (enabled);
