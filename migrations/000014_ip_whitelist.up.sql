-- IP whitelist: trusted source IPs/CIDRs that the response engine must never ban.
-- Detection, alerting and notifications still fire for these IPs (visibility kept);
-- only the progressive-ban recommendation is skipped. `cidr` stores either a single
-- host (e.g. 1.2.3.4 -> /32) or a range (e.g. 10.0.0.0/8).
CREATE TABLE IF NOT EXISTS ip_whitelist (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    cidr       cidr        NOT NULL UNIQUE,
    note       text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
