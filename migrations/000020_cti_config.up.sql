-- Migration 000020 — CTI enrichment config (UI-managed).
-- cache_ttl_hours = dedup window: an IP looked up within it is served from cache and NOT
-- re-queried against the external CTI API (so the API quota is not burned on repeat IPs).
CREATE TABLE IF NOT EXISTS cti_config (
    id              int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    cache_ttl_hours int NOT NULL DEFAULT 24,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
