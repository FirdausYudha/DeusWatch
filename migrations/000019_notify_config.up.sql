-- Migration 000019 — notification config: alert severity threshold + scheduled report
-- delivery to channels (Telegram/email). Channels themselves come from env (secrets).
CREATE TABLE IF NOT EXISTS notify_config (
    id                    int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    min_severity          int NOT NULL DEFAULT 2,  -- 0..4; alerts >= this are sent
    report_interval_hours int NOT NULL DEFAULT 0,  -- 0 = no scheduled report delivery
    report_period_hours   int NOT NULL DEFAULT 24, -- window each delivered report covers
    report_last_sent_at   timestamptz,
    updated_at            timestamptz NOT NULL DEFAULT now()
);
