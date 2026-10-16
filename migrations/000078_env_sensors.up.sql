-- Migration 000078 - environmental sensors (temperature, humidity, door, power).
--
-- Gap 6 of the hospital field insight, and the driver is accreditation rather than comfort:
-- "akreditasinya: CCTV, finger, suhu, APAR, alat kelembapan". A server room held between 18 and 23
-- degrees is a number somebody has to be able to show an assessor.
--
-- Readings are PUSHED, not polled, and that is the whole shape of this table. The hospital named
-- Bardi; every other site names something else. A vendor integration written from here would be a
-- guess about an API nobody on this project can test, which is the same call made for Ruijie
-- (ssh-cli) and for the SNMP sensor OIDs, and it was right both times. Whatever already talks to
-- the device posts the number instead.
--
-- These are NOT folded into snmp_sensors, though the rules are the same shape. An SNMP sensor hangs
-- off a device with a host, a port, credentials and an uptime; an environmental sensor has none of
-- those, and a row carrying host='' port=0 version='push' is a table lying about what it holds.

CREATE TABLE IF NOT EXISTS env_sensors (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    name       text NOT NULL,
    -- Where it physically is, same reason the asset register and the SNMP devices carry one: a
    -- temperature alert nobody can walk to is not actionable.
    location   text NOT NULL DEFAULT '',
    kind       text NOT NULL DEFAULT 'generic',  -- temperature | humidity | door | power | generic
    unit       text NOT NULL DEFAULT '',

    -- The accreditation limits. NULL means no rule in that direction: a room is "18 to 23", which
    -- is both; a fridge is only an upper bound; a fire-panel gauge is only a lower one.
    warn_above double precision,
    warn_below double precision,

    -- The shared secret a device or script presents when posting a reading. Per-sensor rather than
    -- one global token, so a script on a ward PC that is compromised can write readings for the one
    -- sensor it was given and not for the whole estate.
    ingest_key text NOT NULL UNIQUE,

    -- How long silence may last before the SENSOR is the alert. A pushed sensor that stops
    -- reporting leaves its last reading on the board looking perfectly healthy, for days, and
    -- nothing on that screen says the number is old. Silence is the failure an audit asks about,
    -- and it is quiet by nature, so it gets a threshold of its own. 0 disables it.
    stale_after_secs integer NOT NULL DEFAULT 900,

    enabled    boolean NOT NULL DEFAULT true,

    -- Live state, so the board is one indexed read rather than an aggregate over the history.
    last_value double precision,
    last_text  text NOT NULL DEFAULT '',
    last_at    timestamptz,
    breach     text NOT NULL DEFAULT '',
    -- Latched, so one breach produces one alert and one recovery notice rather than one per
    -- reading: a probe sampling every 30 seconds in a warm room would otherwise raise 2,880
    -- alerts a day and teach everyone to mute the channel.
    alerting   boolean NOT NULL DEFAULT false,
    stale_alerting boolean NOT NULL DEFAULT false,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS env_sensors_enabled_idx ON env_sensors (enabled, location, name);

-- One row per reading. Time-series, same day-chunk and retention treatment as the other history
-- tables. 90 days rather than 30: an accreditation assessor asks for the quarter, and this table
-- is tiny next to the interface samples.
CREATE TABLE IF NOT EXISTS env_readings (
    time      timestamptz NOT NULL,
    sensor_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    value     double precision,
    text      text,
    breach    text
);

SELECT create_hypertable(
    'env_readings', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS env_readings_sensor_time_idx ON env_readings (sensor_id, time DESC);
SELECT add_retention_policy('env_readings', INTERVAL '90 days', if_not_exists => TRUE);

-- Tenant isolation, same fail-closed policy every other tenant-scoped table carries (000050).
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['env_sensors','env_readings'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            || 'USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())) '
            || 'WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))', t);
    END LOOP;
END $$;
