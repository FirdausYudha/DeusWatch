-- Migration 000031 - superior FIM one-click restore. An operator requests a restore of a
-- modified/defaced file on a specific agent; the agent polls this over mTLS and writes its
-- known-good snapshot back. One-shot: delivered_at is set when the gateway hands it to the
-- agent so it is not repeated.
CREATE TABLE IF NOT EXISTS file_restores (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_name   text        NOT NULL,
    path         text        NOT NULL,
    status       text        NOT NULL DEFAULT 'requested', -- requested | delivered
    requested_by text        NOT NULL DEFAULT '',
    requested_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_file_restores_pending ON file_restores (agent_name) WHERE status = 'requested';
