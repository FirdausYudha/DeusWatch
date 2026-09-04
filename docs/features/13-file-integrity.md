# 13. File Integrity

A dedicated monitoring page for everything that happens to files on an endpoint: ordinary FIM
changes, ransomware encryption, known-bad hashes and webshell drops.

It exists because these events drown in the Dashboard's mixed stream — one defacement is three
rows among two hundred SSH failures — and because the shared Events table cannot spend column
width on file path, hash verdict and content diff. Here the domain gets its own summary and its
own columns.

**This page is read-only by design.** Restore, quarantine and point-in-time rollback live on the
**Snapshots** page ([design](../adr/0002-versioned-fim-snapshots.md)); every row links across to
it for the exact agent and file, so there is only ever one implementation of a destructive file
action.

## How it works

The page queries `/api/events/search` with `category=file`, which is the category the
normalizer stamps on every FIM event (`internal/ingest/normalize.go`, and `internal/ingest/wazuh.go`
for FIM events arriving from a Wazuh manager). No separate endpoint and no separate storage —
what you see here is the same event stream the Dashboard reads, filtered to one domain.

Each row is classified from the fields the detection rules actually key on, **not** from a label
string (these rules carry no `deuswatch.label` of their own):

| Kind | Signal | Rule | Severity |
|---|---|---|---|
| **ransomware** | `event.action = file_encrypted` | `rules/sigma/ransomware_file_encrypted.yml` | high · `T1486` |
| **malware** | `deuswatch.file_hash.verdict = known_bad` | `rules/sigma/malicious_file_hash.yml` | critical · `T1204.002` |
| **webshell** | rule-name match | `rules/sigma/webshell_upload_containment.yml` | (auto-containment) |
| **file change** | everything else in the category | `rules/sigma/fim_file_change.yml` | `T1565.001` |

One more rule worth knowing about lands in the **file change** bucket:
`rules/sigma/editor_artifact_in_webroot.yml` fires when a vim swap/undo file or an Emacs lock
file is created inside a web root. Nobody edits production web content by hand — git, rsync and
CI never produce those names — so the artifact is evidence that someone had an interactive shell
in the served directory. It is scoped for a very low false-positive rate: creation events only,
inside a web root only, and only on artifact names automation does not generate (`.orig`, `.rej`
and plain `~` backups are deliberately excluded because release tooling does create those). It
declares no `mitigation_action`, which keeps it inside the trusted-session gate, so an admin
editing from a whitelisted IP is treated as an official change and stays silent.

`file_encrypted` is not a guess about the file extension. The agent computes the
**Shannon entropy** of a watched text file and flags the jump when the content turns into
high-entropy random data — encrypted and compressed data sits near 8.0, ordinary config and
source sits far below (`internal/agent/fim.go`). A file that was readable a minute ago and is
now indistinguishable from noise has been encrypted in place, which is the ransomware signal.
A single hit is surfaced; a burst authorizes automatic containment through the aggregation rule.

`event.action` itself carries `file_created`, `file_modified`, `file_deleted` or
`file_encrypted`, shown in the **Action** column with the `file_` prefix stripped.

## How to use

1. Open **File Integrity** (permission `view_dashboard`). The time range comes from the
   picker in the top bar, the same control the Dashboard uses.
2. The four tiles answer the "is anything on fire" question without reading the table:
   file events, ransomware signals, known-bad files, and how many distinct endpoints are
   involved.
3. Narrow with the controls in the table header — free-text search over path/hash/host, a
   **kind** selector, and an **agent** selector.
4. **Click any row** to expand it. You get, when the data is present:
   - **who-data** — the process and user that made the change (requires the Wazuh feed, see
     [`whodata.md`](../whodata.md))
   - the **hash reputation** detail behind a `known bad` verdict
   - the file's **SHA-256**
   - the **content diff** — the exact lines added and removed, which is what tells you whether
     a change was a deployment or a defacement
5. Click **Snapshots ↗** on a row to jump to that file's version timeline, where you can diff
   older versions, restore one, or quarantine the file.

### Editor session — how long the file was actually open

When a file was edited with vim, the expanded row also shows the **editing session**: the clock
time it was opened, the time it was closed, and the duration between them.

This is derived, not reported. vim writes its working file next to the target as
`.<name>.swp` (falling back to `.swo`, then `.swn`), and that file's lifetime *is* the session —
it appears when the buffer opens and is removed when the editor exits cleanly. Both ends are
already ordinary FIM events, so the page correlates them and needs no extra data source. It is
labelled as derived in the UI precisely because it is not who-data: the process and user
attribution comes from the Wazuh feed, this timing does not.

Two partial cases are reported rather than hidden:

- **Opened, never closed.** Either the editor is still running, or it exited uncleanly. A
  leftover `.swp` in a served directory is also an information-disclosure finding in its own
  right — the swap file contains the original file's contents, and a downloadable
  `.index.php.swp` is a classic web-server finding.
- **Closed, opening not in range.** The session started before the selected time window. Widen
  the range to get the full duration.

Only editors that use a side-car working file produce this. A change written by `sed`, a deploy
script, a CMS or an attacker's `curl` has no session to measure, and none is shown — which is
itself informative: a content change with no editing session behind it was not typed by hand.

The table refreshes every 30 seconds, so an incident can be watched as it unfolds without
reloading.

### Reading the summary honestly

The tiles are computed from the rows actually fetched, and the query is capped at **500 rows**.
When that cap is hit the numbers become floors, and the page says so: every tile shows a `≥`
prefix and the first tile's hint names the cap. Narrow the range or the filters to get exact
counts. The page will not quietly under-report.

## Endpoints & storage

| What | Where |
|---|---|
| Event query | `GET /api/events/search?category=file&…` (permission `view_dashboard`) |
| Filters sent | `category`, `q`, `agent`, `from`, `to`, `limit` (500) |
| Page source | `web/src/fim/FileIntegrity.tsx` |
| Storage | none of its own — reads the `events` hypertable like every other view |
| Relevant columns | `event_category`, `event_action`, `file_path`, `file_hash_sha256`, `dw_filehash_verdict`, `dw_filehash_detail`, `file_diff`, `process_name`, `user_name` |

## What feeds it

Nothing appears here until an agent is watching something. FIM watches are configured per
endpoint under **Agents → the endpoint → FIM**, where you set the paths, the snapshot mode
(`baseline`, `on_change`, `scheduled`, `both`), where snapshots are stored (`agent` or
`manager`) and how many versions to keep. See [Agents](05-agents.md).

Two consequences worth knowing:

- **An empty page is the good outcome.** It means nothing changed, not that monitoring is
  broken. To tell the two apart, check that the endpoint has watched paths configured.
- **A content diff needs stored content.** A metadata-only watch, or a binary file, produces an
  event with no diff — the expanded row says so explicitly rather than showing an empty box.

## Related

- [Agents](05-agents.md) — configuring FIM watches, snapshot mode and retention
- [Network Containment](10-network-containment.md) — what a webshell drop can trigger
- [Playbooks](12-playbooks.md) — the remediation steps stamped onto these alerts
- [`whodata.md`](../whodata.md) — attributing a change to a process and user
- [`adr/0002-versioned-fim-snapshots.md`](../adr/0002-versioned-fim-snapshots.md) — the snapshot
  design behind the Snapshots page
