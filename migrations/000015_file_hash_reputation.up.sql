-- Migration 000015 — file-hash reputation cache (FIM hash-reputation).
--
-- Results of looking a file's SHA-256 up against reputation sources (CIRCL hashlookup,
-- VirusTotal) are cached as TTL-bearing rows, mirroring cti_indicators. The worker checks
-- this table before calling an external API, so the free VirusTotal rate limit (≈4/min) is
-- respected and look-ups are deterministic (PRIMARY KEY + UPSERT resolves races).

CREATE TABLE IF NOT EXISTS file_hash_reputation (
    sha256     text        PRIMARY KEY,
    verdict    text        NOT NULL,            -- known_good | known_bad | unknown
    source     text        NOT NULL DEFAULT '', -- e.g. "virustotal,circl"
    detail     text        NOT NULL DEFAULT '', -- e.g. "12/70 engines flagged"
    checked_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL             -- TTL: row is stale after this
);

CREATE INDEX IF NOT EXISTS idx_filehashrep_expires ON file_hash_reputation (expires_at);
