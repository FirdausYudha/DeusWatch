-- Migration 000033 - resume cursors for the OpenSearch/Elasticsearch pull connector.
-- One row per pull integration (keyed by integration id); `cursor` is the JSON search_after
-- value of the last document consumed, so a worker restart resumes without replay or loss.
CREATE TABLE IF NOT EXISTS ingest_cursor (
    name       text PRIMARY KEY,
    cursor     text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);
