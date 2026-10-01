# Software inventory

Each agent reports the host's **installed packages** and **OS/kernel release** to the manager,
viewable on the **[Agent Health](features/15-agent-health.md)** page. This is the foundation for
[Vulnerability Assessment](vulnerability-assessment.md): the agent collects the inventory, the
manager matches it against vulnerability data to produce CVE findings.

## What is collected

- **OS release**: distribution ID, version, codename (from `/etc/os-release`) and kernel
  (`uname -r`). The codename is what scopes a vendor advisory to a release.
- **Installed packages**: name, version, architecture, and **source package**. Debian/Ubuntu via
  `dpkg-query`, RHEL-family via `rpm`. The source package matters because vendor advisories are
  keyed by source, not the binary package.
- **Dependency manifests** (agent v2.15.0+): language lockfiles such as `package-lock.json`,
  `go.sum` or `requirements.txt`, which feed
  [SCA](features/15-agent-health.md#sca-software-composition-analysis). Collection is bounded by
  size, count and depth, and the roots are configurable with `DEUSWATCH_SCA_ROOTS`.

Windows and macOS agents report OS/kernel/arch; package collection there is a later phase.

## How it works

- The agent collects and ships its inventory ~20s after startup, then every **12h**
  (`INVENTORY_INTERVAL`, a Go duration, overrides). Inventory changes slowly, so the cadence is
  deliberately low.
- Each report **replaces** the stored inventory wholesale, a package that was removed disappears,
  rather than lingering and later producing a phantom vulnerability finding.
- Disable entirely with `INVENTORY=0` on the agent.

## Limitations (phase 1)

- **No vulnerability evaluation yet.** This page shows what is installed, not what is vulnerable.
  CVE matching lands in phase 2.
- Third-party software installed outside the package manager (a binary dropped in `/opt`, a
  language package via `pip`/`npm`) is not captured: only what `dpkg`/`rpm` knows about.
