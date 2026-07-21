-- Migration 000047 - software inventory (Vulnerability Assessment, phase 1).
--
-- Each agent reports its OS release and installed packages; the manager stores them here. Phase 2
-- will join agent_packages against a vendor advisory table to produce vulnerability findings, so
-- the columns are the ones OVAL/USN matching needs: the SOURCE package, the exact version, the
-- arch, and (on the OS row) the distro release + codename that scopes an advisory.

-- One row per agent: the OS/kernel summary, refreshed on each report.
CREATE TABLE IF NOT EXISTS agent_os_inventory (
    agent_name  text PRIMARY KEY,
    os_id       text,           -- ubuntu | debian | rhel | ...
    os_version  text,           -- 22.04
    os_codename text,           -- jammy | bookworm  (advisory scope)
    kernel      text,           -- uname -r
    arch        text,           -- amd64 | arm64
    pkg_manager text,           -- dpkg | rpm
    pkg_count   integer NOT NULL DEFAULT 0,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Many rows per agent: the installed packages. Replaced wholesale on each report (an agent's
-- inventory is a snapshot, not an event log), so a removed package disappears rather than lingering.
CREATE TABLE IF NOT EXISTS agent_packages (
    agent_name text NOT NULL,
    name       text NOT NULL,
    version    text NOT NULL,
    arch       text,
    source     text,            -- source package (empty = same as name); phase-2 matching joins on this
    PRIMARY KEY (agent_name, name, arch)
);

-- Phase-2 matching scans by (source-or-name, version) per distro release, and the UI lists an
-- agent's packages; index the common lookups.
CREATE INDEX IF NOT EXISTS idx_agent_packages_agent  ON agent_packages (agent_name);
CREATE INDEX IF NOT EXISTS idx_agent_packages_source ON agent_packages (COALESCE(NULLIF(source,''), name));
