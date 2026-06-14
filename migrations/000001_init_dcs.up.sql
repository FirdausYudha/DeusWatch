-- Migration 000001 — DeusWatch Core Schema (DCS): events hypertable.
--
-- The schema source of truth (Go side) is internal/ingest/schema.go. The columns
-- below = dotted ECS names, snake_cased. Adding a field MUST happen in both places
-- at once (design doc section 7).

CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS events (
    -- identity & time
    id                              uuid        NOT NULL DEFAULT gen_random_uuid(),
    time                            timestamptz NOT NULL,            -- ECS @timestamp

    -- event.*
    event_category                  text,
    event_action                    text,
    event_outcome                   text,
    event_severity                  smallint,                        -- 0..4 (info..critical)
    event_dataset                   text,
    event_original                  text,                            -- raw log line

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

    -- process.* (Phase 2+)
    process_name                    text,
    process_pid                     integer,
    process_command_line            text,

    -- rule.* / threat.* (detection + MITRE auto-label)
    rule_id                         text,
    rule_name                       text,
    threat_technique_id             text,
    threat_technique_name           text,
    threat_tactic_name              text,

    -- threat.indicator.* (CTI enrichment — Phase 2, columns prepared now)
    threat_indicator_ip             inet,
    threat_indicator_confidence     smallint,
    threat_feed_name                text,
    threat_indicator_last_seen      timestamptz,

    -- deuswatch.* (custom namespace)
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
    -- NB: pgvector embedding column for RAG/LLM follows in Phase 3.
);

-- Hypertable with per-DAY chunks (section 8): each day = a separate physical
-- partition, so deleting old data = an instant chunk drop.
SELECT create_hypertable(
    'events', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

-- Indexes for the most frequent dashboard query patterns (always paired with time
-- DESC, since TimescaleDB orders chunks by time).
CREATE INDEX IF NOT EXISTS idx_events_source_ip_time  ON events (source_ip, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity_time   ON events (event_severity, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_category_time   ON events (event_category, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_rule_id_time    ON events (rule_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_host_name_time  ON events (host_name, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_dw_label_time   ON events (dw_label, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_enrich_status   ON events (dw_enrichment_status, time DESC);

-- Columnar compression for chunks > 7 days (section 8): ~90% savings, data stays
-- queryable. segmentby uses event_dataset (low cardinality) — tunable.
ALTER TABLE events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'event_dataset',
    timescaledb.compress_orderby   = 'time DESC'
);
SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE);

-- Default raw-logs retention 30 days (section 8). Can be changed from the UI later;
-- alert/enriched (1 year) & audit (2 years) will have their own policies/tables.
SELECT add_retention_policy('events', INTERVAL '30 days', if_not_exists => TRUE);
