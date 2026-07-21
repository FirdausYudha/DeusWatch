-- Migration 000048 - Vulnerability Assessment phase 2: advisories + findings.
--
-- `advisories` is the cached vendor feed (Ubuntu USN / Debian security tracker): one row per
-- (CVE, source-package, distro release), with the version that fixes it. `agent_vulnerabilities`
-- is the matcher output: an installed package on an agent whose version is below the fixed version.

CREATE TABLE IF NOT EXISTS advisories (
    source        text NOT NULL,          -- feed: usn | debian
    cve           text NOT NULL,
    package       text NOT NULL,          -- SOURCE package the advisory concerns
    release       text NOT NULL,          -- distro codename: jammy | bookworm (distro-specific, so
                                          -- filtering by release alone scopes to the right distro)
    fixed_version text,                    -- NULL/empty = no fix published yet (vulnerable at any version)
    severity      text,
    title         text,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source, cve, package, release)
);

-- The matcher looks advisories up by (release, package) for an agent's installed packages.
CREATE INDEX IF NOT EXISTS idx_advisories_lookup ON advisories (release, package);

CREATE TABLE IF NOT EXISTS agent_vulnerabilities (
    agent_name        text NOT NULL,
    cve               text NOT NULL,
    package           text NOT NULL,       -- source package to upgrade
    installed_version text,
    fixed_version     text,
    severity          text,
    source            text,
    detected_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_name, cve, package)
);

CREATE INDEX IF NOT EXISTS idx_agent_vulns_agent    ON agent_vulnerabilities (agent_name);
CREATE INDEX IF NOT EXISTS idx_agent_vulns_severity ON agent_vulnerabilities (severity);
