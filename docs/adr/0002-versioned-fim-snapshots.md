# ADR 0002 - Versioned FIM Snapshots & Restore-by-Date

- Status: **Complete (build)** — all phases built: 1 (manager config/schema/UI), 2 (agent capture
  + upload; live-verified on the user's agent), 3 (snapshot-now, quarantine-for-analysis, old-vs-
  new diff), restore-by-version, 4 (authorized_change audit event), 5 (manager-side content
  storage, admin-chosen). Manager side verified throughout; the agent-executed pieces (capture,
  quarantine, restore, manager-upload) are verified end-to-end as the user tests on their agent.
- Date: 2026-07-19
- Context: extends the existing single-baseline FIM restore (`internal/agent/fimsnap.go`,
  `internal/store/restores.go`) into a dated, versioned snapshot + one-click restore-by-date
  capability. Backlog item #5.

## Context & problem

Today FIM keeps **one** "known-good" snapshot per watched file — captured the first time the
file is seen — and offers a one-click restore to that single baseline. Two gaps in real use:

1. **No history.** You can only revert to the original first-seen version, not to "how it was
   last Tuesday". Operators want a **timeline of dated versions** and a **restore-by-date**.
2. **Trusted changes are silently suppressed.** The trusted-session gate hides a file-change
   alert when the change happened during a login from a whitelisted admin/IP. That is right for
   *alerting*, but the change should still be **recorded as an authorized-change warning** so
   there is an audit trail — while a sudden change with **no** legitimate session still alarms.

## Decision (agreed with the product owner)

Both major axes are **admin-configurable in DeusWatch**, not hard-coded:

### 1. Snapshot storage location — selectable per deployment (and overridable per watch path)
- **Agent-local** (default): version content is stored on the agent, content-addressed by
  SHA-256 (identical content never duplicated). Only **metadata** (path, hash, size,
  `captured_at`) is shipped to the manager. Restore = the manager sends a "restore path→hash"
  directive; the agent restores from its local content store. Lightest; file content stays on
  the host. Risk: losing the host disk loses the history.
- **Ship to manager**: version content is uploaded and stored centrally (manager disk/DB).
  Restore = the manager sends the content back. History survives host loss; old versions are
  viewable in the UI. Cost: bandwidth + central storage; sensitive file content leaves the host.

### 2. Snapshot trigger — selectable per deployment
- **On every detected change** (with a per-file version cap / age retention).
- **Scheduled** (e.g. daily) snapshot of all watched files.
- **Both** (daily baseline + extra version on each change).

### 3. Always-warn on trusted changes
Add a low-severity **`authorized_change`** signal: when the trusted-session gate would suppress
a file-change alert, still emit an info/low event (audit trail) instead of dropping it silently.
Sudden changes without a legitimate session keep their normal alert severity.

## Consequences

- New agent config fields (snapshot mode, trigger, retention, per-path storage override) flow
  through the existing central agent-config push.
- Agent protocol gains: (a) snapshot **metadata** upload, (b) optional content upload (manager
  mode), (c) a **restore-to-version** directive (extends the current restore feed).
- New DB tables: `fim_snapshots` (path, agent, sha256, size, captured_at, storage, trigger) and,
  for manager-mode, a content blob store (or object path). Migration required.
- New API + UI: a per-file **snapshot timeline** with a date picker and a one-click Restore.
- Honesty: the whole path must be **verified on a real Linux agent** before it is claimed
  working (implemented ≠ verified) — the reason this is staged, not built blind.

## Limits & tuning (large HTML/PHP)

- **Snapshot size ceiling** — only TEXT files up to `maxSnapshotBytes` are versioned (diff +
  restore); larger files are still change-DETECTED by hash, but get no version/diff/restore.
  Default **2 MiB** (was 256 KiB), overridable with **`FIM_SNAPSHOT_MAX_BYTES`** (plain bytes or a
  `K`/`M` suffix, e.g. `4M`). Raising it costs agent memory (the file is read whole) and, in
  manager-storage mode, upload bandwidth + central DB space — the admin's call.
- **Diff safety** — the old-vs-new diff is a full O(m·n) LCS. To keep it from exhausting memory on
  a large file, when `lines_old × lines_new > maxDiffCells` (2M) it falls back to a cheap O(m+n)
  "~X added / ~Y removed" summary. The version + restore are unaffected (both are O(size)).
- **Manager-mode upload cap** — the agent's snapshot uploader flushes by accumulated bytes so a
  batch of large files never exceeds the gateway's 8 MiB body limit. A single manager-stored
  version's content is therefore practically bounded to ~7 MiB; agent-mode uploads only metadata,
  so it has no wire limit (bounded only by agent memory / the size ceiling above).

## Phased build plan

1. **Config + schema (manager-side, testable without an agent):** agent-config fields;
   `fim_snapshots` table (migration); store CRUD; `GET /api/fim/snapshots?path=` timeline;
   Settings/Agents UI toggles (storage mode, trigger, retention). *Verifiable locally.*
2. **Agent capture (BUILT 2026-07-19):** `SnapshotStore.SaveVersion`/`ReadVersion` (content-
   addressed blob store under `<dir>/blobs/<sha256>`, de-duplicated); the FIM scanner captures a
   version on-change and/or on a schedule (`FIM_SNAPSHOT_SCHEDULE` override) per the source's
   `snapshot_mode`; metadata ships via `POST /v1/snapshots` (mTLS) → gateway `SnapshotHandler` →
   `RecordSnapshot(storage="agent")`. Manager side unit- + integration-tested; *end-to-end capture
   still needs verification on the user's Linux agent.*
3. **Restore-by-date:** manager "restore path→version" directive + agent restore; UI timeline +
   date picker + one-click Restore. *Verify end-to-end on the agent.*
4. **Always-warn:** `authorized_change` low-severity event from the trusted-session gate.
5. **Manager-storage mode:** content upload + central store + restore-from-manager. *Optional,
   after agent-local mode is proven.*

## Status / next step

Design accepted. Build starts at **Phase 1** (manager-side config + schema + UI), which is fully
verifiable on the local stack; Phases 2–3 require the user's real Linux agent for honest
verification. Target release: **v1.17.0**.
