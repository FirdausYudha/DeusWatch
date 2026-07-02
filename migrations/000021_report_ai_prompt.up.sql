-- Migration 000021 - custom prompt template for the AI report summary.
-- summary_prompt overrides the built-in system prompt (empty/NULL = use the default).
ALTER TABLE report_ai_config ADD COLUMN IF NOT EXISTS summary_prompt text NOT NULL DEFAULT '';
