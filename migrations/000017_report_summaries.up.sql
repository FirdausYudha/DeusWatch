-- Migration 000017 — AI-generated report summaries (on-demand + scheduled).
-- Each row is one executive summary the LLM produced for a time window; the UI shows
-- the latest. Keeping history lets scheduled summaries accumulate.
CREATE TABLE IF NOT EXISTS report_summaries (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    period_hours int         NOT NULL,
    summary      text        NOT NULL,
    model        text        NOT NULL DEFAULT '',
    generated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_report_summaries_generated ON report_summaries (generated_at DESC);
