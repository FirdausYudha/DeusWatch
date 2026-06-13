-- Migrasi 000004 — registrasi agent & token enrollment (design doc bagian 4 & 12).

-- Agent terdaftar. Tiap agent punya sertifikat client UNIK (CN = name); revoked
-- = true membuat gateway menolak koneksinya. Kolom config untuk config-push.
CREATE TABLE IF NOT EXISTS agents (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text UNIQUE NOT NULL,
    os           text,
    cert_serial  text,
    enrolled_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    config       jsonb,
    revoked      boolean NOT NULL DEFAULT false
);

-- Token enrollment sekali-pakai, masa berlaku pendek. Disimpan sebagai HASH.
CREATE TABLE IF NOT EXISTS agent_enroll_tokens (
    token_hash    text PRIMARY KEY,
    created_by    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    used_by_agent uuid REFERENCES agents(id) ON DELETE SET NULL
);
