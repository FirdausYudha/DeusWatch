-- Migrasi 000006 — response engine (Fase 2): aksi blokir dengan approval workflow
-- & ban progresif (design doc bagian 9, namespace deuswatch.remediation.*).
--
-- Tiap rekomendasi blokir dicatat di sini sebagai 'recommended'. Analyst/admin
-- meng-approve -> engine mengeksekusi via responder (nftables/Mikrotik/CrowdSec) ->
-- 'executed'. Riwayat per-IP dipakai menghitung ban progresif (offense_count).

CREATE TABLE IF NOT EXISTS response_actions (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at    timestamptz NOT NULL DEFAULT now(),
    source_ip     inet        NOT NULL,
    action        text        NOT NULL DEFAULT 'block',  -- block (unblock menyusul)
    reason        text,                                  -- rule/label pemicu
    rule_id       text,
    ban_seconds   integer     NOT NULL DEFAULT 0,        -- 0 = permanen
    offense_count integer     NOT NULL DEFAULT 1,        -- ke-berapa kali IP ini diblok
    source        text        NOT NULL DEFAULT 'playbook', -- playbook | llm
    status        text        NOT NULL DEFAULT 'recommended', -- recommended|approved|executed|dismissed|failed
    responder     text,                                  -- backend yang mengeksekusi
    decided_by    text,                                  -- username yang approve/dismiss
    decided_at    timestamptz,
    executed_at   timestamptz,
    error         text
);

CREATE INDEX IF NOT EXISTS idx_response_status     ON response_actions (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_response_source_ip  ON response_actions (source_ip, created_at DESC);
