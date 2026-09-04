-- Migration 000062, service liveness, so the manager can tell when a backend component stops.
--
-- Why this exists: on 2026-09-04 the worker container was absent for 11+ hours and the dashboard
-- showed nothing wrong. The worker is the only consumer of logs.normalized and the only caller of
-- InsertEvent, so its absence silently kills the entire detection pipeline, no events, no
-- brute-force, no FIM, no notifications. Worse, AGENT_DISCONNECT_AFTER (the "an agent went quiet"
-- alarm) runs INSIDE the worker, so the component that reports trouble was the one that vanished.
--
-- The heartbeat goes through the database rather than an HTTP probe on purpose: the api and the
-- worker already share this connection, it needs no new network path or service discovery, and it
-- keeps working when the two run on different hosts.
--
-- Not tenant-scoped: this is infrastructure state, identical for every tenant, so it is
-- deliberately left out of the RLS-forced set (migration 000050) and readable by any authenticated
-- caller with view_dashboard.
CREATE TABLE IF NOT EXISTS service_heartbeats (
    -- One row per component ("worker", and room for others later). Upserted on the primary key,
    -- so a restarted or re-scheduled container reuses its row instead of accumulating history,
    -- this table answers "is it alive right now", not "when did it run".
    service      text        PRIMARY KEY,
    last_seen_at timestamptz NOT NULL,
    -- What the component reports about itself: its build, and a free-text note for anything worth
    -- surfacing next to the liveness state.
    version      text        NOT NULL DEFAULT '',
    detail       text        NOT NULL DEFAULT ''
);
