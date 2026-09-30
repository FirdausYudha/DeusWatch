-- Migration 000065: Software Composition Analysis (SCA) storage.
--
-- Agents ship language dependency manifests (lockfiles) with their inventory; the manager scans them
-- with Trivy and stores per-agent findings for the Agent Health page. Both tables are snapshots keyed
-- by agent name (replaced wholesale on each report/scan), mirroring agent_packages / agent_vulnerabilities.

-- Raw dependency manifests as reported by the agent, kept so the worker can re-scan them without
-- another agent round-trip (e.g. after a Trivy DB refresh).
CREATE TABLE IF NOT EXISTS agent_manifests (
    agent_name text NOT NULL,
    path       text NOT NULL,   -- absolute path on the host (also gives Trivy the right filename)
    content    text NOT NULL,   -- raw manifest text
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_name, path)
);
CREATE INDEX IF NOT EXISTS idx_agent_manifests_agent ON agent_manifests (agent_name);

-- SCA findings: a vulnerable language package in one of an agent's manifests.
CREATE TABLE IF NOT EXISTS agent_sca_findings (
    agent_name        text NOT NULL,
    target            text NOT NULL DEFAULT '',   -- manifest the package came from
    pkg_type          text NOT NULL DEFAULT '',   -- ecosystem: npm | gomod | pip | gem | ...
    pkg_name          text NOT NULL,
    installed_version text NOT NULL DEFAULT '',
    fixed_version     text,
    vuln_id           text NOT NULL,              -- CVE-... or GHSA-...
    severity          text,                       -- critical|high|medium|low|negligible|unknown
    PRIMARY KEY (agent_name, vuln_id, pkg_name, installed_version)
);
CREATE INDEX IF NOT EXISTS idx_agent_sca_agent ON agent_sca_findings (agent_name);
