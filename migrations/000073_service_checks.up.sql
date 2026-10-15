-- Migration 000073 - service/API health checks (layer-7 uptime monitoring).
--
-- The problem this exists for, in the words of the hospital's own onsite engineer: "Di dashboard
-- kita itu ping, ping-nya oke, oke bisa. Tapi ada beberapa kadang edit enggak bisa. Kemudian
-- finger-nya enggak bisa." Their BPJS integration fails one web service at a time while ICMP and
-- the host stay perfectly up, so the infra dashboard reads green while the registration desk
-- cannot register a patient. Outages are learned from an unofficial Telegram group, or from the
-- counter complaining.
--
-- So this is deliberately NOT host monitoring. A check targets one ENDPOINT and asserts what that
-- endpoint is supposed to do, and every check carries a business-function group ("pendaftaran",
-- "klaim", "finger") so the screen answers "which function is down", not "which host answers ping".

CREATE TABLE IF NOT EXISTS service_checks (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    name            text NOT NULL,
    service_group   text NOT NULL DEFAULT '',      -- business function: pendaftaran | klaim | finger
    kind            text NOT NULL DEFAULT 'http',  -- http | tcp
    target          text NOT NULL,                 -- URL for http, host:port for tcp
    method          text NOT NULL DEFAULT 'GET',
    -- 0 means "any non-error response" (2xx/3xx). A specific code is for the endpoints that answer
    -- 200 with a failure in the body, or that legitimately answer 401/404 when they are healthy.
    expect_status   integer NOT NULL DEFAULT 0,
    -- Request headers as an ENCRYPTED JSON object. The BPJS web services need a username and token
    -- on every call, and those are credentials: they are sealed with the same secret box the LLM
    -- and connector credentials use, never stored as plaintext.
    headers_enc     text,
    -- A body substring that must be present for the check to pass. The endpoints that return 200
    -- with {"metaData":{"code":"201"}} inside are exactly the ones a status-code check misses.
    expect_body     text,
    interval_secs   integer NOT NULL DEFAULT 60,
    timeout_secs    integer NOT NULL DEFAULT 10,
    -- 0 disables the latency rule. A service that answers in 9s is technically up and practically
    -- down at a registration counter, which is the distinction the counter staff actually feel.
    latency_warn_ms integer NOT NULL DEFAULT 0,
    -- Consecutive failures before an alert fires. One failed probe across the public internet is
    -- noise; three in a row is an outage. Without this the hospital would get paged by packet loss.
    fail_threshold  integer NOT NULL DEFAULT 3,
    enabled         boolean NOT NULL DEFAULT true,

    -- Live state, maintained by the prober so the status page is one indexed read, not an
    -- aggregate over the history table on every page load.
    last_checked_at timestamptz,
    last_ok         boolean,
    last_status     integer,
    last_latency_ms integer,
    last_error      text,
    consec_failures integer NOT NULL DEFAULT 0,
    -- Latched when an alert has been raised, cleared on recovery, so one outage produces one alert
    -- and one recovery notice rather than one per probe interval.
    alerting        boolean NOT NULL DEFAULT false,

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS service_checks_enabled_idx ON service_checks (enabled, service_group);

-- One row per probe. This is time-series at (checks x interval) rate, so it is a hypertable with
-- the same day-chunk + retention treatment the events table gets: answering "since when has this
-- been down" needs history, but not forever.
CREATE TABLE IF NOT EXISTS service_check_results (
    time       timestamptz NOT NULL,
    check_id   uuid        NOT NULL,
    tenant_id  uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    ok         boolean     NOT NULL,
    status     integer,
    latency_ms integer,
    error      text
);

SELECT create_hypertable(
    'service_check_results', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS service_check_results_check_time_idx
    ON service_check_results (check_id, time DESC);

SELECT add_retention_policy('service_check_results', INTERVAL '30 days', if_not_exists => TRUE);

-- Tenant isolation, same fail-closed policy every other tenant-scoped table carries (000050).
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['service_checks','service_check_results'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            || 'USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())) '
            || 'WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))', t);
    END LOOP;
END $$;
