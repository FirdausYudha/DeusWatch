# Ransomware defense in DeusWatch

Ransomware is a **layered** problem — no single feature "solves" it. DeusWatch focuses on the two
layers a security platform can own well — **detect it fast** and **stop it spreading** — plus a
**recovery** aid for the files it versions. It is **not** a backup product; pair it with immutable
off-host backups for full recovery (see *Honest limits*).

## The layers

| Layer | Goal | DeusWatch |
|---|---|---|
| Prevent | stop execution | out of scope (EDR / app-allowlisting / patching) |
| **Detect** | see the encryption early | mass file-change burst, shadow-copy deletion, ransom-note rules + FIM who-data |
| **Contain** | stop the spread | **network containment** — isolate the host from the LAN (except the manager) |
| **Recover** | roll files back | versioned FIM snapshots + restore-by-version (for watched small text files) |
| Backup | full recovery | **external immutable backups** (restic / borg / ZFS snapshots / object-lock) |

## 1. Detect

- **Mass file encryption by host** — a burst of file changes on one host in a short window is a
  hallmark of ransomware. `rules/sigma/agg/ransomware_mass_change_containment.yml` fires at
  `> 200 changes / 2 min per host` (level **critical**) and **authorizes containment**. A lower-
  severity `fim_change_burst.yml` (`> 100 / 5 min`) alerts without containment.
- **Shadow-copy deletion** (`ransomware_shadowcopy_containment.yml`) — deleting VSS copies
  (`vssadmin delete shadows`, `wmic shadowcopy delete`) is a precursor ransomware step; fires
  **critical** and authorizes containment.
- **Who-data** — on Linux, FIM tells you **which process/user** made the change, so the alert
  names the ransomware process.
- **Ransom notes / extensions** — add a single-event rule matching filenames like `*.locked`,
  `README*DECRYPT*` to catch the note drop.

> **Tuning & false positives:** a large legitimate **deploy** can also trip the mass-change rule.
> That's why containment is **recommend-only by default** (an analyst approves it in the Response
> page) — it only auto-isolates when `CONTAINMENT_AUTO=1` **and** the alert severity meets the
> rule's `criticality_threshold`. Tune the threshold/timeframe to your environment. A precise
> **content-entropy** signal (text → encrypted) is a planned enhancement to cut false positives.

## 2. Contain

An alert that authorizes `network_containment` drives the response engine to **isolate the host**:
the agent self-firewalls (drops all traffic except the manager + allow-list) and the host's IP is
blocked at the edge. This **stops the ransomware reaching file servers, storage and other users**,
and protects the manager-stored snapshots. See [docs/features/10-network-containment.md](features/10-network-containment.md).

- Default is **recommend-only**; set `CONTAINMENT_AUTO=1` to auto-isolate on qualifying alerts.
- Auto-release after the rule's `timeout` (default 30 min) or manual release.

## 3. Recover — versioned FIM snapshots

For the files DeusWatch versions (see [ADR 0002](adr/0002-versioned-fim-snapshots.md)), you can
**revert to a pre-attack version**:

- **Store snapshots on the MANAGER** (per FIM source → Snapshots → Store = *on manager*). This is
  critical for ransomware: agent-local snapshots can be encrypted along with everything else on
  the host, but manager-stored versions live **off-host** and survive.
- Old versions are **never overwritten** — the clean pre-attack version stays available even after
  the encrypted version is captured.
- **Restore-by-version** rolls a file back to a chosen dated version (one click; the current
  content is snapshotted first). *Bulk point-in-time revert* (restore a whole directory to a
  timestamp) is planned.

## Honest limits

- **Coverage.** FIM snapshots version **small watched TEXT files** (config/source, up to
  `FIM_SNAPSHOT_MAX_BYTES`, default 2 MiB). Ransomware also hits documents, databases and
  binaries — those are **not** recoverable from snapshots. Use **immutable backups** for full
  recovery.
- **Timing.** Containment stops the **spread** (to shares and other hosts) and saves off-host
  snapshots; the hit host may already be **partially encrypted** before isolation. Detecting and
  isolating fast limits, not eliminates, damage.
- **Snapshot location matters.** Agent-local snapshots are only a convenience revert, not a
  ransomware control — use **manager storage** for ransomware resilience.
- DeusWatch is one layer. Keep EDR/app-allowlisting (prevent) and immutable backups (recover)
  alongside it.

## Recommended setup for ransomware resilience

1. Watch the directories that matter (webroot, config, source) with a **fim** source, **Snapshots
   = on_change**, **Store = on manager**.
2. Enable the ransomware detection rules (bundled) and tune the mass-change threshold.
3. Decide on `CONTAINMENT_AUTO` (auto-isolate) vs analyst approval for your risk tolerance.
4. Keep **immutable off-host backups** for full-system recovery.
