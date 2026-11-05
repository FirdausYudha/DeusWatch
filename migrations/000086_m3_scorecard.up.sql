-- Migration 000086 - M3 performance scorecard (Kartu Kinerja).
--
-- The hospital IT team judges itself on a report card: coverage, detection rate, how fast it sees
-- an attack (MTTD) and how fast it responds (MTTR), benchmark score, false-positive ratio, and how
-- long a report takes to prepare. M3 computes those eight indicators for a chosen period and gives
-- each a predicate (Efektif / Cukup / Perlu Perbaikan) against a fixed threshold, grouped by NIST
-- CSF function.
--
-- Four tables support it:
--   * scenario_runs      - the controlled-test log (imported from catatan_skenario.csv); feeds the
--                          detection rate, MTTD and MTTR.
--   * alert_reviews      - a reviewer's verdict on an alert (false positive or not); feeds the
--                          false-positive ratio.
--   * scorecard_thresholds - the predicate bands, seeded once below. No editing screen is needed.
--   * scorecard_inputs   - manual figures that have no automated source yet, e.g. report prep time.

-- ── scenario_runs : one repetition of one controlled-test scenario ────────────────────────────
CREATE TABLE IF NOT EXISTS scenario_runs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    scenario_id   text NOT NULL,                 -- S1 .. S13
    repetition    int  NOT NULL,                 -- 1, 2, 3
    executed_at   timestamptz,                   -- when the attack/trigger was run
    alerted_at    timestamptz,                   -- when the alert actually appeared (null = not detected)
    responded_at  timestamptz,                   -- when a real response ran / a ticket was picked up (null = none)
    rule_or_feature text NOT NULL DEFAULT '',
    technique     text NOT NULL DEFAULT '',      -- ATT&CK technique, e.g. T1110
    detected      boolean NOT NULL DEFAULT false,
    note          text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now()
);
-- One row per scenario per repetition per tenant: a re-import updates in place rather than piling up.
CREATE UNIQUE INDEX IF NOT EXISTS scenario_runs_uniq_idx ON scenario_runs (tenant_id, scenario_id, repetition);

-- ── alert_reviews : a reviewer's verdict on one alert ─────────────────────────────────────────
-- events live in the events_data hypertable; we reference an event by its id as text (no FK across
-- the hypertable). One verdict per event per tenant.
CREATE TABLE IF NOT EXISTS alert_reviews (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    event_id      text NOT NULL,
    false_positive boolean NOT NULL DEFAULT false,
    reviewed_by   text NOT NULL DEFAULT '',
    reviewed_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS alert_reviews_uniq_idx ON alert_reviews (tenant_id, event_id);

-- ── scorecard_thresholds : predicate bands per indicator (seeded; no edit screen) ─────────────
-- higher_is_better: value >= effective -> Efektif, >= sufficient -> Cukup, else Perlu Perbaikan.
-- else (lower is better): value <= effective -> Efektif, <= sufficient -> Cukup, else Perlu Perbaikan.
CREATE TABLE IF NOT EXISTS scorecard_thresholds (
    indicator_key    text PRIMARY KEY,
    csf_function     text NOT NULL,              -- Identify | Protect | Detect | Respond | Govern
    label            text NOT NULL,
    unit             text NOT NULL DEFAULT '',   -- %, menit, hari
    higher_is_better boolean NOT NULL,
    effective        numeric NOT NULL,
    sufficient       numeric NOT NULL,
    sort_order       int NOT NULL DEFAULT 0
);

INSERT INTO scorecard_thresholds
    (indicator_key, csf_function, label, unit, higher_is_better, effective, sufficient, sort_order)
VALUES
    ('source_coverage',     'Identify', 'Cakupan sumber data aktif',        '%',    true,  95, 80, 1),
    ('detection_rate',      'Detect',   'Tingkat deteksi skenario',         '%',    true,  90, 75, 2),
    ('mttd',                'Detect',   'MTTD (median deteksi)',            'menit', false, 5,  15, 3),
    ('mttr',                'Respond',  'MTTR (median respons)',            'menit', false, 15, 60, 4),
    ('benchmark_score',     'Protect',  'Skor benchmark CIS',               '%',    true,  80, 60, 5),
    ('false_positive_ratio','Detect',   'Rasio positif palsu',              '%',    false, 10, 25, 6),
    ('bridging_detection',  'Detect',   'Deteksi gangguan bridging (S11)',  '%',    true,  90, 75, 7),
    ('report_prep_time',    'Govern',   'Waktu penyiapan laporan',          'hari',  false, 1,  3,  8)
ON CONFLICT (indicator_key) DO NOTHING;

-- ── scorecard_inputs : manual figures with no automated source yet ────────────────────────────
CREATE TABLE IF NOT EXISTS scorecard_inputs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    input_key   text NOT NULL,                   -- e.g. report_prep_time
    value       numeric NOT NULL,
    recorded_by text NOT NULL DEFAULT '',
    recorded_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scorecard_inputs_key_idx ON scorecard_inputs (tenant_id, input_key, recorded_at DESC);

-- ── Tenant isolation (fail-closed), same policy as every other tenant-scoped table (000050) ───
-- scorecard_thresholds is global reference data, so it carries no tenant_id and no RLS.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['scenario_runs','alert_reviews','scorecard_inputs'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            || 'USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())) '
            || 'WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))', t);
    END LOOP;
END $$;
