-- Migration 000085 - vendor accounts and their allowed access windows (RV-01, M2).
--
-- A hospital lets an outside vendor into the SIMRS server to maintain it, but only during agreed
-- hours. Access at 3am from a vendor account is the signal, and it is a signal a Sigma rule cannot
-- express: Sigma matches a single event's fields and has no notion of "the clock says it is now
-- outside the window". So the window lives in a table and a periodic evaluator in the worker reads
-- it, the same shape the environmental monitor uses for a reading that has gone stale.
--
-- Identified by account name, matched against the user on a successful login. The field report
-- expects vendor accounts to carry a `vnd-` prefix by convention (Tabel IV.11), but this table is
-- the authority on which accounts are vendor accounts, not the prefix: a convention in a username
-- is a reminder for humans, not an access control.

CREATE TABLE IF NOT EXISTS vendor_accounts (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    -- The login account this window governs, e.g. vnd-acme. Matched against events.user_name.
    account    text NOT NULL,
    -- Allowed weekdays as ISO numbers: 1=Monday .. 7=Sunday. Empty means no day is allowed, which
    -- would alert on every login; the API rejects an empty set so that cannot happen by accident.
    days       smallint[] NOT NULL DEFAULT '{1,2,3,4,5}',
    -- The allowed window within an allowed day, in the account's own timezone. A window that wraps
    -- midnight (start > end) is allowed and handled by the evaluator.
    start_time time NOT NULL DEFAULT '08:00',
    end_time   time NOT NULL DEFAULT '17:00',
    -- IANA timezone, e.g. Asia/Jakarta. The vendor's contract is written in local time, and a
    -- hospital in WIB must not have its window silently evaluated in UTC.
    timezone   text NOT NULL DEFAULT 'Asia/Jakarta',
    enabled    boolean NOT NULL DEFAULT true,
    note       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- One window per account per tenant: two rows for the same account would make "allowed" ambiguous.
CREATE UNIQUE INDEX IF NOT EXISTS vendor_accounts_tenant_acct_idx ON vendor_accounts (tenant_id, account);
CREATE INDEX IF NOT EXISTS vendor_accounts_enabled_idx ON vendor_accounts (enabled);

-- Tenant isolation, same fail-closed policy every other tenant-scoped table carries (000050).
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['vendor_accounts'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I '
            || 'USING (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids())) '
            || 'WITH CHECK (current_is_superadmin() OR tenant_id = ANY(current_tenant_ids()))', t);
    END LOOP;
END $$;
