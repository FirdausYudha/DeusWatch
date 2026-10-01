-- Migration 000067: OSV vulnerability record cache.
--
-- The OSV API returns only vulnerability IDs from a batch package query; the severity, CVSS and
-- per-release fixed version need one GET per ID. Those records barely change, so they are cached
-- here: the first scan of a fleet fetches a few thousand, every later scan fetches only IDs it has
-- never seen. Without this, every scan would re-fetch thousands of records over the network.
CREATE TABLE IF NOT EXISTS osv_vulns (
    id         text PRIMARY KEY,          -- OSV id, e.g. UBUNTU-CVE-2024-11053
    cve        text NOT NULL DEFAULT '',  -- upstream CVE id
    severity   text NOT NULL DEFAULT '',  -- critical|high|medium|low|negligible|unknown
    cvss       double precision,          -- CVSS v3 base score (NULL = none published)
    fixed      jsonb NOT NULL DEFAULT '{}'::jsonb, -- "<ecosystem>|<package>" -> fixed version
    cached_at  timestamptz NOT NULL DEFAULT now()
);
