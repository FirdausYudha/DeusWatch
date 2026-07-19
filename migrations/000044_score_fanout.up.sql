-- Migration 000044 - cross-agent fan-out in the composite IP score.
-- One source IP probing MANY of our endpoints is campaign behaviour, not a stray probe, so the
-- scorer now folds in how many distinct agents the IP touched in the window. Stored alongside the
-- other signals so the UI can show "hit N endpoints" and the score stays explainable.
ALTER TABLE ip_scores ADD COLUMN IF NOT EXISTS agents int NOT NULL DEFAULT 0;
