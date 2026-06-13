-- Migrasi 000001 — DeusWatch Core Schema (DCS): hypertable events.
--
-- Sumber kebenaran schema (sisi Go) ada di internal/ingest/schema.go. Kolom di
-- bawah = nama dotted ECS yang di-snake_case-kan. Penambahan field WAJIB serentak
-- di kedua tempat (design doc bagian 7).

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS events (
    -- identitas & waktu
    id                              uuid        NOT NULL DEFAULT gen_random_uuid(),
    time                            timestamptz NOT NULL,            -- ECS @timestamp

    -- event.*
    event_category                  text,
    event_action                    text,
    event_outcome                   text,
    event_severity                  smallint,                        -- 0..4 (info..critical)
    event_dataset                   text,
    event_original                  text,                            -- baris log mentah

    -- source.* / destination.*
    source_ip                       inet,
    source_port                     integer,
    source_geo_country_iso          text,
    source_geo_city                 text,
    destination_ip                  inet,
    destination_port                integer,

    -- host.* / agent.*
    host_name                       text,
    host_os_type                    text,
    host_ip                         inet,
    agent_id                        text,
    agent_version                   text,

    -- user.*
    user_name                       text,
    user_domain                     text,

    -- network.*
    network_protocol                text,
    network_transport               text,

    -- file.* (FIM)
    file_path                       text,
    file_hash_sha256                text,
    file_owner                      text,
    file_mode                       text,

    -- process.* (Fase 2+)
    process_name                    text,
    process_pid                     integer,
    process_command_line            text,

    -- rule.* / threat.* (deteksi + auto-label MITRE)
    rule_id                         text,
    rule_name                       text,
    threat_technique_id             text,
    threat_technique_name           text,
    threat_tactic_name              text,

    -- threat.indicator.* (enrichment CTI — Fase 2, kolom disiapkan sekarang)
    threat_indicator_ip             inet,
    threat_indicator_confidence     smallint,
    threat_feed_name                text,
    threat_indicator_last_seen      timestamptz,

    -- deuswatch.* (namespace custom)
    dw_enrichment_status            text DEFAULT 'pending',
    dw_enrichment_abuse_confidence  smallint,
    dw_enrichment_otx_pulse_count   integer,
    dw_label                        text,
    dw_llm_verdict                  text,
    dw_llm_summary                  text,
    dw_llm_analyzed_at              timestamptz,
    dw_severity_original            smallint,
    dw_severity_escalated_by        text,
    dw_remediation_action           text,
    dw_remediation_source           text,
    dw_remediation_status           text
    -- NB: kolom embedding pgvector untuk RAG/LLM menyusul di Fase 3.
);

-- Hypertable dengan chunk per-HARI (bagian 8): tiap hari = partisi fisik terpisah,
-- sehingga penghapusan data lama = drop chunk yang instan.
SELECT create_hypertable(
    'events', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

-- Indeks untuk pola query dashboard tersering (selalu disertai time DESC karena
-- TimescaleDB mengurut chunk berdasarkan waktu).
CREATE INDEX IF NOT EXISTS idx_events_source_ip_time  ON events (source_ip, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity_time   ON events (event_severity, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_category_time   ON events (event_category, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_rule_id_time    ON events (rule_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_host_name_time  ON events (host_name, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_dw_label_time   ON events (dw_label, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_enrich_status   ON events (dw_enrichment_status, time DESC);

-- Kompresi kolumnar untuk chunk > 7 hari (bagian 8): hemat ~90%, data tetap bisa
-- di-query. segmentby memakai event_dataset (kardinalitas rendah) — bisa di-tune.
ALTER TABLE events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'event_dataset',
    timescaledb.compress_orderby   = 'time DESC'
);
SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE);

-- Retensi default raw logs 30 hari (bagian 8). Dapat diubah dari UI nanti;
-- alert/enriched (1 tahun) & audit (2 tahun) akan punya kebijakan/tabel sendiri.
SELECT add_retention_policy('events', INTERVAL '30 days', if_not_exists => TRUE);
