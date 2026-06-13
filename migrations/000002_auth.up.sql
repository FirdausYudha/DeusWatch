-- Migrasi 000002 — autentikasi, sesi, dan audit log (design doc bagian 4).

-- Pengguna. Password di-hash Argon2id (lihat internal/auth). totp_secret untuk 2FA.
CREATE TABLE IF NOT EXISTS users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    role          text NOT NULL DEFAULT 'viewer',  -- viewer | analyst | admin
    disabled      boolean NOT NULL DEFAULT false,
    totp_secret   text,                            -- diisi saat 2FA diaktifkan
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Sesi: token dengan rotasi (bukan JWT berumur panjang). Yang disimpan adalah
-- HASH token, bukan token mentah.
CREATE TABLE IF NOT EXISTS sessions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   text NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_seen_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

-- Audit log APPEND-ONLY: semua aksi yang mengubah state tercatat (bagian 4).
CREATE TABLE IF NOT EXISTS audit_log (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    time       timestamptz NOT NULL DEFAULT now(),
    actor      text NOT NULL,           -- username pelaku
    actor_role text NOT NULL,
    action     text NOT NULL,           -- login, block_ip, edit_rule, dst.
    target     text,                    -- objek aksi
    detail     text,                    -- konteks tambahan (teks/JSON)
    source_ip  inet
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log (time DESC);

-- Tegakkan append-only: tolak UPDATE/DELETE pada audit_log.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log bersifat append-only: % ditolak', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
CREATE TRIGGER trg_audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
