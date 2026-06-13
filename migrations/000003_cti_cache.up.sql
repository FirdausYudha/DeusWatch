-- Migrasi 000003 — cache CTI ber-TTL (design doc bagian 3).
--
-- Hasil lookup CTI disimpan sebagai BARIS di Postgres dengan kolom TTL (expires_at),
-- BUKAN cache in-memory. Worker mengecek tabel ini sebelum memanggil API eksternal;
-- PRIMARY KEY pada ip + UPSERT (ON CONFLICT) menyelesaikan race antar-worker secara
-- deterministik — tidak pernah "tabrakan cache".

CREATE TABLE IF NOT EXISTS cti_indicators (
    ip               inet        PRIMARY KEY,
    abuse_confidence smallint    NOT NULL DEFAULT 0,   -- 0..100 (AbuseIPDB)
    otx_pulse_count  integer     NOT NULL DEFAULT 0,   -- jumlah pulse OTX
    country_iso      text,
    feed_name        text,
    checked_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL              -- TTL: baris dianggap basi setelah ini
);

CREATE INDEX IF NOT EXISTS idx_cti_expires ON cti_indicators (expires_at);
