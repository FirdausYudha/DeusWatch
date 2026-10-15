-- Migration 000076 - SNMP monitoring of network devices.
--
-- Gap 7 of the hospital field insight. Their SNMP data is split across three tools — The Dude for
-- the switches, WIS Cloud for the access points, Grafana at head office — and the ask was one
-- dashboard. The devices already speak SNMP, so nothing new is installed on them.
--
-- On the schema's shape, the thing worth knowing: SNMP standardises much less than people expect.
-- Uptime, the device's name and description, and the interface table are identical everywhere, so
-- they are columns. CPU load, temperature and power-supply state have NO standard OID — every
-- vendor puts them somewhere different — so they are rows in snmp_sensors, supplied by the
-- operator. That is why this works on the Ruijie gear it was built for, and would keep working on
-- Aruba after a contract change, without a single vendor OID baked into the product.

CREATE TABLE IF NOT EXISTS snmp_devices (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    name           text NOT NULL,
    -- Where it physically is. The field team manage ~20 hospitals and asked for assets to carry a
    -- location; a switch identified only by IP is a switch nobody can go and look at.
    location       text NOT NULL DEFAULT '',
    host           text NOT NULL,
    port           integer NOT NULL DEFAULT 161,
    version        text NOT NULL DEFAULT '2c',   -- 2c | 3

    -- v3 identity. Not secret, so stored plainly; the passwords are not here.
    v3_user        text NOT NULL DEFAULT '',
    v3_level       text NOT NULL DEFAULT 'authPriv',  -- noAuthNoPriv | authNoPriv | authPriv
    v3_auth_proto  text NOT NULL DEFAULT 'SHA',
    v3_priv_proto  text NOT NULL DEFAULT 'AES',

    -- The community string and both v3 passphrases, as ONE encrypted JSON object, sealed with the
    -- same secret box the connector and service-check credentials use. A community string is a
    -- password that happens to have a friendly name: read it and you can read the whole device.
    creds_enc      text,

    poll_secs      integer NOT NULL DEFAULT 60,
    -- Walking the interface table is the expensive half: a 48-port switch is 48 rows per poll, and
    -- twenty of them are over a million rows a day. Worth it where port state matters, wasteful
    -- where only the device's own health does, so it is a per-device decision and defaults to off.
    poll_ifaces    boolean NOT NULL DEFAULT false,
    -- Consecutive failed polls before an alert. One lost UDP packet is not an outage; SNMP runs
    -- over UDP and a single timeout means very little.
    fail_threshold integer NOT NULL DEFAULT 3,
    enabled        boolean NOT NULL DEFAULT true,

    -- Live state, so the device board is one indexed read rather than an aggregate over history.
    last_polled_at timestamptz,
    last_ok        boolean,
    last_error     text,
    sys_name       text NOT NULL DEFAULT '',
    sys_descr      text NOT NULL DEFAULT '',
    uptime_secs    bigint NOT NULL DEFAULT 0,
    consec_failures integer NOT NULL DEFAULT 0,
    -- Latched, so one outage produces one alert and one recovery notice.
    alerting       boolean NOT NULL DEFAULT false,

    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS snmp_devices_enabled_idx ON snmp_devices (enabled, location, name);

-- The operator-defined half: CPU, temperature, fan, PSU, free memory — whatever this vendor
-- exposes and at whatever OID. The team already pull these through The Dude, so the OIDs are
-- something they have rather than something they must research.
CREATE TABLE IF NOT EXISTS snmp_sensors (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    device_id  uuid NOT NULL REFERENCES snmp_devices(id) ON DELETE CASCADE,
    name       text NOT NULL,
    oid        text NOT NULL,
    unit       text NOT NULL DEFAULT '',
    -- Multiplies the raw value. Devices report tenths of a degree and percent-times-ten often
    -- enough that without this an operator reads 345 where the switch means 34.5 °C.
    scale      double precision NOT NULL DEFAULT 1,
    -- NULL means no rule in that direction. warn_below is for the sensors where LOW is the fault:
    -- free memory, fan RPM, a PSU reporting 1 for healthy.
    warn_above double precision,
    warn_below double precision,
    position   integer NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS snmp_sensors_device_idx ON snmp_sensors (device_id, position);

-- One row per sensor per poll. Time-series, so the same day-chunk + retention treatment the other
-- history tables get.
CREATE TABLE IF NOT EXISTS snmp_readings (
    time      timestamptz NOT NULL,
    device_id uuid        NOT NULL,
    sensor_id uuid        NOT NULL,
    tenant_id uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    value     double precision,
    -- The text a non-numeric sensor returned, and the breach message when a threshold was broken.
    text      text,
    breach    text
);

SELECT create_hypertable(
    'snmp_readings', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS snmp_readings_sensor_time_idx ON snmp_readings (sensor_id, time DESC);
SELECT add_retention_policy('snmp_readings', INTERVAL '30 days', if_not_exists => TRUE);

-- One row per interface per poll, only for devices with poll_ifaces on. Counters are stored raw:
-- SNMP counters are monotonic and wrap, so a rate has to be computed from the difference between
-- two samples, and storing a rate here would bake in whatever interval happened to be configured
-- at the time.
CREATE TABLE IF NOT EXISTS snmp_iface_samples (
    time         timestamptz NOT NULL,
    device_id    uuid        NOT NULL,
    tenant_id    uuid        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    if_index     integer     NOT NULL,
    name         text        NOT NULL DEFAULT '',
    admin_status smallint    NOT NULL DEFAULT 0,
    oper_status  smallint    NOT NULL DEFAULT 0,
    in_octets    bigint      NOT NULL DEFAULT 0,
    out_octets   bigint      NOT NULL DEFAULT 0,
    in_errors    bigint      NOT NULL DEFAULT 0,
    out_errors   bigint      NOT NULL DEFAULT 0
);

SELECT create_hypertable(
    'snmp_iface_samples', 'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists       => TRUE
);

CREATE INDEX IF NOT EXISTS snmp_iface_samples_device_time_idx
    ON snmp_iface_samples (device_id, time DESC);
-- Shorter than the sensor history on purpose: this is by far the largest table here, and "which
-- port flapped last week" is worth less than the disk it costs at twenty switches.
SELECT add_retention_policy('snmp_iface_samples', INTERVAL '14 days', if_not_exists => TRUE);

-- Tenant isolation, same fail-closed policy every other tenant-scoped table carries (000050).
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['snmp_devices','snmp_sensors','snmp_readings','snmp_iface_samples'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            || 'USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())) '
            || 'WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))', t);
    END LOOP;
END $$;
