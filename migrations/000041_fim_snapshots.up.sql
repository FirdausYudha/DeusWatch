-- Migration 000041 - versioned FIM snapshots (ADR 0002, Phase 1).
-- Each row is one dated version of a watched file, captured by an agent's FIM snapshotter. This
-- extends the single first-seen baseline into a timeline the UI can browse and restore FROM by
-- date. `storage` records where the version CONTENT lives: 'agent' (content-addressed on the
-- host; only this metadata is shipped) or 'manager' (content uploaded into `content`). `trigger`
-- records what captured it. Identical consecutive versions are de-duplicated by the agent, so a
-- new row means the file actually changed (or a scheduled baseline was taken).
CREATE TABLE IF NOT EXISTS fim_snapshots (
    id          bigserial   PRIMARY KEY,
    agent_name  text        NOT NULL,
    path        text        NOT NULL,
    sha256      text        NOT NULL,
    size        bigint      NOT NULL DEFAULT 0,
    storage     text        NOT NULL DEFAULT 'agent',      -- agent | manager
    trigger     text        NOT NULL DEFAULT 'on_change',  -- on_change | scheduled
    captured_at timestamptz NOT NULL DEFAULT now(),
    content     bytea                                       -- only when storage='manager' (Phase 5); else NULL
);
CREATE INDEX IF NOT EXISTS idx_fim_snapshots_agent_path_time ON fim_snapshots (agent_name, path, captured_at DESC);
