-- Migration 000042 - FIM file actions + version diff (ADR 0002, Phase 3).
-- agent_file_actions is a manager→agent work queue for on-demand file operations the operator
-- triggers from the Snapshots UI: "snapshot_now" (capture a version immediately) and "quarantine"
-- (move the current on-disk file into the agent's quarantine dir, read-only, for blue-team
-- analysis). The agent polls requested rows, acts, and writes the outcome back into result.
CREATE TABLE IF NOT EXISTS agent_file_actions (
    id           bigserial   PRIMARY KEY,
    agent_name   text        NOT NULL,
    path         text        NOT NULL,
    action       text        NOT NULL,                 -- snapshot_now | quarantine
    status       text        NOT NULL DEFAULT 'requested', -- requested | delivered | done | failed
    requested_by text,
    result       text,                                  -- e.g. the quarantine destination, or an error
    created_at   timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    result_at    timestamptz
);
CREATE INDEX IF NOT EXISTS idx_agent_file_actions_agent_status ON agent_file_actions (agent_name, status);
CREATE INDEX IF NOT EXISTS idx_agent_file_actions_agent_path   ON agent_file_actions (agent_name, path, created_at DESC);

-- Each captured version carries the unified diff against the previously-captured version of the
-- same file (computed on the agent), so the UI can show "old vs new" without fetching content.
ALTER TABLE fim_snapshots ADD COLUMN IF NOT EXISTS diff text;
