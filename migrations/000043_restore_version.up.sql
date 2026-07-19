-- Migration 000043 - restore-by-version (ADR 0002). Extends the on-demand file-action queue with
-- a target version hash, so an operator can restore a watched file to a SPECIFIC dated version
-- from the Snapshots timeline (not just the single baseline). The agent resolves the hash against
-- its content-addressed blob store and writes that version back atomically.
ALTER TABLE agent_file_actions ADD COLUMN IF NOT EXISTS version_sha256 text;
