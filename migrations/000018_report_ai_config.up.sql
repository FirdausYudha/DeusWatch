-- Migration 000018 — schedule for the AI report summary.
-- interval_hours = how often the worker auto-generates a summary (0 = disabled).
-- period_hours   = the time window each summary covers.
CREATE TABLE IF NOT EXISTS report_ai_config (
    id            int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    interval_hours int NOT NULL DEFAULT 0,
    period_hours   int NOT NULL DEFAULT 24,
    updated_at    timestamptz NOT NULL DEFAULT now()
);
