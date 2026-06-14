-- Migration 000002 — authentication, sessions, and audit log (design doc section 4).

-- Users. Passwords are hashed with Argon2id (see internal/auth). totp_secret for 2FA.
CREATE TABLE IF NOT EXISTS users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username      text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    role          text NOT NULL DEFAULT 'viewer',  -- viewer | analyst | admin
    disabled      boolean NOT NULL DEFAULT false,
    totp_secret   text,                            -- set when 2FA is enabled
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Sessions: rotating tokens (not long-lived JWTs). What is stored is the token
-- HASH, not the raw token.
CREATE TABLE IF NOT EXISTS sessions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   text NOT NULL UNIQUE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_seen_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

-- APPEND-ONLY audit log: every state-changing action is recorded (section 4).
CREATE TABLE IF NOT EXISTS audit_log (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    time       timestamptz NOT NULL DEFAULT now(),
    actor      text NOT NULL,           -- acting username
    actor_role text NOT NULL,
    action     text NOT NULL,           -- login, block_ip, edit_rule, etc.
    target     text,                    -- action object
    detail     text,                    -- extra context (text/JSON)
    source_ip  inet
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log (time DESC);

-- Enforce append-only: reject UPDATE/DELETE on audit_log.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % rejected', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
CREATE TRIGGER trg_audit_log_immutable
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
