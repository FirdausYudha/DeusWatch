# Ransomware kill-switch — live demo playbook

How to show, end to end, that DeusWatch detects a process encrypting files and lets an operator
stop it by killing its PID. This is a controlled, benign simulation — no real ransomware.

> **Read this first.** The agent-side kill (actually terminating a process) is unit-tested but has
> not been exercised against a live process before. **Do a full dry run yourself before showing
> anyone.** The dry run is identical to the demo, so any problem surfaces to you, not to your boss.

## What the audience sees (the story)

1. A rogue process starts encrypting files in a watched directory.
2. Within seconds, DeusWatch flags **file encryption** and, because it knows *which* process did it,
   raises a **kill recommendation** on the Response page — it does **not** kill anything on its own.
3. The operator reviews it and clicks **Kill process**.
4. The agent re-verifies the process is still the culprit and terminates it. The UI shows
   **killed**, and the rogue process is gone.

The human-in-the-loop is the selling point: DeusWatch proposes, a person decides, and only then does
it act — with the agent double-checking before it pulls the trigger.

## Prerequisites (make-or-break — check every one)

This demo simply will not produce a recommendation unless all of these are true on the Linux host:

1. **Agent on v2.1.1**, rebuilt and restarted. Older agents have no kill-switch and no entropy
   detection.
2. **Process attribution is ON.** The recommender refuses to propose a kill it can't attribute to a
   process, so this is the #1 thing people miss:
   - `auditd` installed (`sudo apt-get install -y auditd`),
   - the agent running **as root**,
   - `AGENT_WHODATA=1` in the agent's environment.
   Without who-data there is no PID → **no recommendation ever appears.**
3. **A FIM source watching the demo directory.** In the manager UI → Agents → your agent, add a
   source: type `fim`, path `/srv/demo-data` (the throwaway dir used below).
4. **Recommend-only mode (the default).** Leave `KILL_SWITCH_AUTO` unset — you *want* the manual
   approval step for the demo. (Auto-kill exists but hides the best part.)

Confirm who-data is live after restart:

```bash
journalctl -u deuswatch-agent | grep -i who-data
#   agent: who-data active (audit watch on N path(s) ...)   <- good
```

## The benign "ransomware" (throwaway, reversible)

This encrypts files in a **dedicated demo directory only**, and — crucially — the encrypting
process **stays alive afterwards** so the kill-switch has a live PID to stop. (A one-shot script
would exit and the kill would report `skipped_gone` — nothing to kill.)

Save as `/tmp/demo-cryptor.py` on the host:

```python
#!/usr/bin/env python3
# BENIGN ransomware simulation for the DeusWatch kill-switch demo.
# Overwrites files in a throwaway dir with random bytes, then stays running.
import os, time

DIR = "/srv/demo-data"
os.makedirs(DIR, exist_ok=True)

# Seed some "documents" as ordinary text, then let the agent see them once.
for i in range(1, 6):
    with open(f"{DIR}/report{i}.txt", "w") as f:
        f.write(f"quarterly report {i} - confidential\n" * 50)
print("[demo] seeded text documents; waiting for the agent to baseline them...")
time.sleep(20)

# "Encrypt": overwrite each with 64 KiB of high-entropy random data. THIS process does the writes,
# so who-data attributes the encryption to THIS pid — and we keep it alive to be killed.
for name in os.listdir(DIR):
    with open(os.path.join(DIR, name), "wb") as f:
        f.write(os.urandom(64 * 1024))
print(f"[demo] files encrypted by pid {os.getpid()}; staying alive for the kill-switch")
while True:
    time.sleep(5)
```

Give it an obvious villainous name so the demo reads clearly and it's plainly not a protected
system process:

```bash
cp /tmp/demo-cryptor.py /tmp/cryptor && chmod +x /tmp/cryptor
```

## Dry run (do this before the boss)

1. Ensure the prerequisites above, then run the simulation:
   ```bash
   sudo python3 /tmp/cryptor
   ```
   (Run as root so the write is attributed the same way it will be in the real demo.)
2. Watch the manager: **Dashboard → Events** should show a **file_encrypted** event within ~15s,
   and **Response → Ransomware kill-switch** should list a recommendation naming `python3`/`cryptor`
   with its PID.
3. Click **Kill process**. Confirm:
   - the UI row shows **killed** (green), and
   - on the host the process is gone (`ps aux | grep cryptor` → nothing).
4. If instead you see:
   - **no recommendation at all** → who-data/auditd isn't active (prereq #2), or the FIM source
     isn't watching `/srv/demo-data` (prereq #3);
   - **`skipped_gone`** → the process exited before you approved (make sure you're running the
     staying-alive script above, not a one-shot);
   - **`skipped_no_identity`** → who-data attributed no start time; check auditd;
   - **`failed`** → tell me the exact result string; this is the path we haven't live-tested, and
     I'll fix it before you demo.

Only once the dry run ends in **killed** are you clear to show your boss.

## The live demo (2 minutes)

1. Open **Response → Ransomware kill-switch** on the projector.
2. On the host: `sudo python3 /tmp/cryptor`. Narrate: "this is malware encrypting our files."
3. Within seconds the recommendation appears. Point out that DeusWatch **knew which process** did it
   and **did not act on its own** — it's asking a human.
4. Click **Kill process**. The row turns to **killed**; show `ps aux | grep cryptor` is empty.
5. Point out the honesty of the status: only an actual termination is green; a refusal (protected
   process, or the PID no longer matching) would be shown in amber — the tool never claims a kill it
   didn't make.

## Cleanup

```bash
rm -rf /srv/demo-data /tmp/cryptor /tmp/demo-cryptor.py
```

## Fallback if auditd can't be ready in time

If you cannot enable who-data before the meeting, you can still demonstrate the **approve → kill**
mechanism by seeding one recommendation directly (ask me for the exact SQL) and running a
long-lived dummy process for it to target. It shows the operator flow and the real kill, but skips
the automatic detection — so prefer the full chain above if at all possible.

## Auto mode (v2.6+)

The default is recommend-only: every proposed kill waits for a human to click Approve. From v2.6
onward the kill-switch can auto-approve **high-confidence triggers** — YARA content-scan matches
(docs/yara.md), agent-measured ransomware entropy (`file_encrypted`), and file hashes flagged by
≥10 vendors in reputation feeds. Everything softer stays recommend-only.

### Turn it on

1. Fill the process whitelist first (`Response → Kill-switch auto-approval → Process whitelist`).
   The default already covers systemd, sshd, dockerd, postgres, nginx, nats-server, and the
   DeusWatch services themselves. Add anything else that would take your box down if killed.
2. Verify who-data (auditd) attribution works on a test host — no attribution means no auto-kill
   regardless of the toggle, so it's important the mechanism is confirmed before turning auto on.
3. Flip **Enable auto-approve for high-confidence triggers**. The badge on the card changes to
   `auto ON`. The worker picks up the new policy within ~30s (same reload cadence as the ban
   policy) — no restart needed.

Alternative: set `KILL_SWITCH_AUTO=1` in the worker's environment. Env wins over the DB toggle
(useful for a declarative deploy that must survive a DB rewrite).

### Guard rails (always on, even in auto mode)

- **PID ≤ 100 is never auto-killed.** Covers kernel threads, init, systemd, early-boot daemons on
  every Linux distro DeusWatch runs on.
- **Whitelisted process names are never auto-killed.** Case-insensitive match on `procName`.
- **Attribution is mandatory.** No `process.start` and no `process.command_line` → no auto-kill.
  A recommendation the agent couldn't verify would only ever produce a refusal.
- **Rate limit per agent** — default 3 auto-kills per minute. Beyond that the trigger degrades to
  recommend-only and the operator sees the burst on the dashboard instead of silently losing 100
  processes to a bad rule.

When a guard rail blocks an auto-kill the worker still writes the recommendation (auto=false) and
logs the reason (`respond: auto-kill blocked by guard rail (PID 42 ≤ 100…)`) — nothing gets
silently dropped.

### Audit

Auto-kills record their trigger in `agent_file_actions.requested_by`:
`auto:yara`, `auto:ransomware`, `auto:filehash`, `auto:ransom_rule`. Human approvals still record
the operator's username. Filter the FIM Actions table by requester when reviewing what fired.
