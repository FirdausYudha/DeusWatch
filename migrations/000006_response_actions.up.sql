-- Migration 000006 — response engine (Phase 2): block actions with an approval workflow
-- & progressive ban (design doc section 9, namespace deuswatch.remediation.*).
--
-- Each block recommendation is recorded here as 'recommended'. An analyst/admin
-- approves -> the engine executes via a responder (nftables/Mikrotik/CrowdSec) ->
-- 'executed'. Per-IP history drives the progressive ban (offense_count).

CREATE TABLE IF NOT EXISTS response_actions (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at    timestamptz NOT NULL DEFAULT now(),
    source_ip     inet        NOT NULL,
    action        text        NOT NULL DEFAULT 'block',  -- block (unblock to follow)
    reason        text,                                  -- triggering rule/label
    rule_id       text,
    ban_seconds   integer     NOT NULL DEFAULT 0,        -- 0 = permanent
    offense_count integer     NOT NULL DEFAULT 1,        -- how many times this IP was blocked
    source        text        NOT NULL DEFAULT 'playbook', -- playbook | llm
    status        text        NOT NULL DEFAULT 'recommended', -- recommended|approved|executed|dismissed|failed
    responder     text,                                  -- backend that executes
    decided_by    text,                                  -- username that approved/dismissed
    decided_at    timestamptz,
    executed_at   timestamptz,
    error         text
);

CREATE INDEX IF NOT EXISTS idx_response_status     ON response_actions (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_response_source_ip  ON response_actions (source_ip, created_at DESC);
