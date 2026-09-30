-- Migration 000066: CVSS scores on findings + a scan-status row so the UI can show why a scan
-- produced nothing (e.g. Trivy could not reach its DB) instead of silently showing stale "unknown".

ALTER TABLE agent_vulnerabilities ADD COLUMN IF NOT EXISTS cvss double precision;
ALTER TABLE agent_sca_findings     ADD COLUMN IF NOT EXISTS cvss double precision;

-- One row per scanner ("trivy-os" | "trivy-sca"): whether the last run succeeded and a human detail.
CREATE TABLE IF NOT EXISTS scan_status (
    scanner    text PRIMARY KEY,
    ok         boolean NOT NULL,
    detail     text NOT NULL DEFAULT '',
    scanned    integer NOT NULL DEFAULT 0,   -- agents scanned in the last run
    updated_at timestamptz NOT NULL DEFAULT now()
);
