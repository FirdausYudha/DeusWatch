-- CVE priority cache (v2.8.0). Ubuntu's notices.json feed carries no per-CVE severity, so USN
-- findings previously landed with severity="unknown". The worker now enriches by calling
-- ubuntu.com/security/CVE-YYYY-NNNN.json once per CVE and reading the `priority` field
-- (negligible|low|medium|high|critical). Cache lives here so the same CVE is never fetched twice
-- inside its TTL. This is a plain lookup table with no tenant column — CVE priorities are global
-- public data, and every tenant benefits from the same cache.
CREATE TABLE IF NOT EXISTS cve_priority_cache (
    cve         text        PRIMARY KEY,
    priority    text        NOT NULL,                                   -- "" when Ubuntu doesn't publish one
    checked_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL                                    -- caller decides TTL (30 days by default)
);
CREATE INDEX IF NOT EXISTS idx_cve_priority_cache_expires ON cve_priority_cache (expires_at);
