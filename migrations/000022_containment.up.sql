-- Migration 000022 — network containment (host isolation).
--
-- When a rule with `mitigation_action: network_containment` fires on a compromised host,
-- the response engine records the isolation here. The agent (identified by its cert CN =
-- agent_id) polls its directive, derived from the active row, and firewalls itself off from
-- the LAN except the manager. The IP (when known) is also blocked at the network edge.
--
-- The partial unique index enforces anti-double-containment: an agent can have at most ONE
-- open (recommended/contained) record at a time, so concurrent alerts collapse to one action.

CREATE TABLE IF NOT EXISTS containment_actions (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    agent_id        text        NOT NULL,                       -- agent cert CN / name
    host_name       text,                                       -- reported hostname (context)
    ip              inet,                                       -- host IP for the edge block (nullable)
    reason          text,                                       -- triggering rule/label
    rule_id         text,
    timeout_seconds integer     NOT NULL DEFAULT 0,             -- 0 = until manual release
    status          text        NOT NULL DEFAULT 'recommended', -- recommended|contained|released|dismissed|failed
    auto            boolean     NOT NULL DEFAULT false,         -- was it auto-contained?
    decided_by      text,                                       -- who approved/released (or 'auto')
    contained_at    timestamptz,
    expires_at      timestamptz,                                -- auto-release deadline (from timeout)
    released_at     timestamptz,
    error           text                                        -- non-fatal note (e.g. edge block failed)
);

CREATE INDEX IF NOT EXISTS idx_containment_status ON containment_actions (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_containment_agent  ON containment_actions (agent_id, created_at DESC);

-- At most one open containment per agent (anti-double-containment / no looping).
CREATE UNIQUE INDEX IF NOT EXISTS uq_containment_open
    ON containment_actions (agent_id)
    WHERE status IN ('recommended', 'contained');
