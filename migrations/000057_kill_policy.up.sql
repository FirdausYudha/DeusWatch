-- Kill-switch auto-approval policy (docs/auto-kill.md). Singleton row (id=1); values are read at
-- worker startup + reloaded on the same schedule as the ban policy. Fail-closed: if the row is
-- missing or unreadable the engine falls back to recommend-only.
CREATE TABLE IF NOT EXISTS kill_policy (
    id                  smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    -- Master switch. false = every kill stays a recommendation (existing behaviour).
    auto_approve        boolean     NOT NULL DEFAULT false,
    -- Process names that are NEVER auto-killed regardless of what the alert says. Default set
    -- covers the "kill this and you break the whole box" list on a typical Linux server.
    whitelist           text[]      NOT NULL DEFAULT ARRAY[
                                        'systemd','init','sshd','dockerd','containerd',
                                        'postgres','mysqld','nginx','apache2','nats-server',
                                        'deuswatch-agent','deuswatch-worker','deuswatch-api',
                                        'deuswatch-gateway'
                                    ],
    -- Per-agent auto-kill rate ceiling. Beyond this the trigger degrades to recommend-only and a
    -- "kill_rate_limited" alert fires so the operator sees the burst.
    rate_limit_per_min  integer     NOT NULL DEFAULT 3 CHECK (rate_limit_per_min BETWEEN 1 AND 60),
    updated_at          timestamptz NOT NULL DEFAULT now()
);
INSERT INTO kill_policy (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
