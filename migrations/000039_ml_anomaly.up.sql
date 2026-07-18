-- Migration 000039 - the ML-bridge (LST Tameng Lapis 5 <-> Lapis 3).
-- ip_anomaly holds the anomaly_score written back by the external Isolation Forest batch; the
-- worker's composite scorer reads it and folds it into the score (weight is UI-tunable, 0 by
-- default). ip_scores gains an anomaly column so the value is visible alongside the score.
CREATE TABLE IF NOT EXISTS ip_anomaly (
    ip         inet PRIMARY KEY,
    anomaly    int NOT NULL DEFAULT 0, -- 0..100
    updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE ip_scores ADD COLUMN IF NOT EXISTS anomaly int NOT NULL DEFAULT 0;
