# 15. Agent Health

Two questions about an endpoint that are usually answered by two different tools: *what known
vulnerabilities does the software on this machine have*, and *what known vulnerabilities do the
libraries my applications depend on have*. Agent Health puts both on one page, per endpoint, because
an operator patching a host wants one list to work from, not two consoles to reconcile.

| Tab | Scope | Source of truth |
|---|---|---|
| **Vulnerability Assessment** | OS packages (`dpkg` / `rpm`) | The agent's package inventory |
| **SCA** | Application dependencies (npm, PyPI, Go, ...) | Dependency lockfiles found on the host |

Both are **server-side**. The agent only ever collects and ships facts; nothing scans, matches or
downloads a vulnerability database on your endpoints. That keeps the agent small and means a
vulnerability-data problem is a manager problem, not a fleet-wide one.

## Vulnerability Assessment

The OS-package half. Fully documented in
[vulnerability-assessment.md](../vulnerability-assessment.md), including how to choose between the
OSV, Trivy and built-in sources. In short: the agent reports its packages and OS release, the
manager asks the configured source which CVEs affect them, and findings are stored per agent with
severity, CVSS and the fixed version.

The table supports **filtering by severity** and shows the **accumulated count per severity** as
clickable chips, so "show me only the criticals on this host" is one click rather than a scroll.

## SCA (Software Composition Analysis)

OS package managers do not know about the libraries your applications pull in. A Django app's
`requirements.txt` or a Node service's `package-lock.json` can be months behind on a critical CVE
while `apt` reports the machine fully patched. SCA closes that gap.

### How it works

1. **Collect.** The agent walks a bounded set of roots for dependency lockfiles and ships their
   contents with its inventory. It is deliberately conservative: it skips dependency stores
   (`node_modules`, `vendor`), VCS metadata and pseudo-filesystems, caps file size, total file count
   and depth, and skips any file containing a NUL byte (that is a binary file that happens to share
   a lockfile's name, not something parseable).
2. **Parse.** The manager turns each lockfile into a list of package URLs.
3. **Query.** Those go through the same OSV pipeline and record cache as the OS packages.
4. **Report.** Findings are stored per agent with the vulnerability ID, severity, CVSS, the fixed
   version, and **which manifest the dependency came from**, so you know which file to edit.

### Formats parsed

| Ecosystem | File |
|---|---|
| npm | `package-lock.json` (v1 and v2/v3) |
| Go | `go.sum` |
| PyPI | `requirements.txt` (pinned `==` only) |
| Packagist | `composer.lock` |
| crates.io | `Cargo.lock` |
| RubyGems | `Gemfile.lock` |

Not parsed yet: `pom.xml`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`,
`gradle.lockfile`. The agent still collects some of these, so adding a parser is a manager-side
change that needs no fleet redeploy.

Only **pinned, resolved** versions are usable. A range like `urllib3>=1.0` is skipped: without an
exact version there is nothing to match against, and guessing would produce false positives.

### Where it looks

By default: `/home`, `/opt`, `/srv`, `/var/www`, `/app`, `/usr/local/src`. Override per agent with
`DEUSWATCH_SCA_ROOTS` (colon- or comma-separated). Set it to an empty value to disable collection.

If an agent finds nothing it says so explicitly in its own log, naming the roots it searched, rather
than leaving an empty SCA page to be interpreted:

```
agent: inventory reported (ubuntu 24.04, 922 packages, 56 dependency manifests)
```

## Requirements

- **Agent v2.15.0+** for SCA. Older agents report packages but collect no manifests, so the
  Vulnerability Assessment tab works while SCA stays empty.
- **Internet on the manager** for the vulnerability source (see the source table in
  [vulnerability-assessment.md](../vulnerability-assessment.md)).

When a scan fails or has nothing to work with, the page says which of those it was in a banner, with
the underlying error. An empty page is never left to mean "you are safe".

## How to use

1. **Agent Health** in the sidebar, pick an endpoint on the left.
2. **Vulnerability Assessment** tab: the severity donut, the accumulated per-severity counts, and
   the CVE table. Filter to one severity with the chips or the dropdown.
3. **SCA** tab: the same shape for dependencies, with the manifest path on each row.
4. Work top-down: the table is sorted worst severity first, then highest CVSS.

## Endpoints & storage

| What | Where |
|---|---|
| Per-agent OS findings | `GET /api/vulnerabilities`, `GET /api/vulnerabilities/agent?agent=` |
| Per-agent SCA findings | `GET /api/sca`, `GET /api/sca/agent?agent=` |
| OS findings table | `agent_vulnerabilities` (`cvss` added in migration `000066`) |
| Dependency manifests | `agent_manifests` (migration `000065`) |
| SCA findings | `agent_sca_findings` (migration `000065`) |
| Vulnerability record cache | `osv_vulns` (migration `000067`) |
| Last scan outcome | `scan_status` (migration `000066`), surfaced as the banner |
| UI | `web/src/health/AgentHealth.tsx` |

## Known gaps

- **Java is not covered.** `pom.xml` and `gradle.lockfile` are collected but not parsed.
- **The first scan is slow.** Populating the vulnerability record cache for a large fleet means
  thousands of sequential detail requests. Subsequent scans are fast; the work is cached, not
  repeated.
- **No per-finding suppression.** There is no way yet to mark a CVE as accepted-risk or
  not-applicable, so the list is raw rather than triaged.
- **SCA sees files, not running processes.** A lockfile in a directory nobody deploys from is still
  reported, and a vendored dependency with no lockfile is not reported at all.
