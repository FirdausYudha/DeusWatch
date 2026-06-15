-- Migration 000010 — per-user customizable dashboard layouts.
-- Each user stores their own widget layout (Kibana-style) as opaque JSON.

CREATE TABLE IF NOT EXISTS user_dashboards (
    user_id    uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    layout     jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
