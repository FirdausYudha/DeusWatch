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

- **Encryption signal (entropy)** — the agent computes each changed file's byte **Shannon
  entropy**; a watched **text** file that turns into **high-entropy random data** (`>= 7.2`
  bits/byte, tunable via `FIM_ENTROPY_THRESHOLD`) is flagged `event.action: file_encrypted` — a
  *precise* ransomware signal, since a normal deploy produces readable text, not encrypted bytes.
  `ransomware_file_encrypted.yml` surfaces a single hit (high);
  `ransomware_encryption_burst_containment.yml` fires on `> 15 encrypted files / 2 min per host`
  (critical) and **authorizes containment** — far fewer false positives than a raw mass-change burst.
- **Mass file change by host** — a broader burst of *any* file changes (encryption, defacement, or
  a runaway process). `ransomware_mass_change_containment.yml` fires at `> 200 changes / 2 min per
  host` (critical, authorizes containment); the lower-severity `fim_change_burst.yml`
  (`> 100 / 5 min`) alerts only. Prefer the entropy rule for precision; keep this as a backstop.
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
> rule's `criticality_threshold`. Tune the threshold/timeframe to your environment. The
> **entropy signal** above (text → encrypted) is the precise, low-false-positive path — prefer it.

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

## Kill-switch: terminating the encrypting process

Reverting files undoes damage; the kill-switch stops it continuing. When DeusWatch detects a
process encrypting files, it can terminate that process — the most destructive action the
platform takes, and therefore the most heavily gated.

### How a kill is authorized

Four gates in series. Each can only reduce what happens, and any one of them can stop it.

1. **Evidence.** Only ransomware-class alerts qualify: a measured entropy jump
   (`event.action: file_encrypted`), or a ransomware rule that explicitly authorized automated
   response. Ordinary file changes never propose a kill.
2. **Attribution.** The alert must name a process. On Linux that means **auditd who-data must be
   enabled** — without it there is no PID, and DeusWatch proposes nothing rather than guessing.
3. **Human approval.** Detection writes an inert *recommendation*. An analyst with
   `approve_remediation` authorizes it on **Response → Ransomware kill-switch**. Setting
   `KILL_SWITCH_AUTO=1` skips this gate; the rest still apply.
4. **Agent re-verification.** The agent independently re-checks and may refuse. Its refusal is
   final — the manager cannot override it.

### Why the agent re-verifies (PID reuse)

A PID is not a stable identity. Between detection and approval the target can exit and the OS can
hand its PID to an unrelated process — Windows recycles aggressively. Killing on a PID alone would
eventually kill something innocent.

So the agent captures the process **start time** at detection, and refuses unless the live process
still matches it (falling back to the executable path when no start time is available). A request
carrying no identity at all is refused outright rather than executed hopefully.

### What is never killed

`init`/PID 1, session and login paths (`sshd`, `winlogon`, `lsass`, `csrss`, …), the container
runtime, and the DeusWatch agent itself — even when the evidence is perfect. A false positive
there turns a contained incident into an outage, or disables the responder.

Add your own with `KILL_PROTECTED=sapstartsrv,oracle` on the agent (comma-separated process
names). DeusWatch cannot know which processes are business-critical for you.

`explorer.exe` is deliberately **not** protected: injection into the user shell is a real
ransomware technique, so shielding it would defeat the feature. Losing a shell is recoverable.

### Reading the outcome honestly

`done` means the agent finished *deciding*, not that a process died. The result says what actually
happened, and only `killed` means the process is gone:

| Result | Meaning |
| --- | --- |
| `killed` | The process was terminated (verified — the agent re-read it afterwards). |
| `skipped_protected` | Refused: protected process. **Still running.** |
| `skipped_mismatch` | Refused: the PID no longer matches the detected process. **Still running.** |
| `skipped_no_identity` | Refused: nothing to verify against. **Still running.** |
| `skipped_gone` | The process had already exited. Nothing was killed. |
| `failed` | The kill was attempted and did not work. **Still running.** |

The UI colours only `killed` as success; every "still running" outcome is amber.

### Limitations

- **Linux only for automatic proposals**, because attribution needs auditd who-data. The kill
  mechanism itself works on Windows, but without who-data nothing proposes a kill there yet.
- Killing the process does **not** decrypt files. Pair it with point-in-time revert (above).
- A process can spawn children; the kill-switch terminates the attributed PID, not a tree.
