# Auto-kill PID — contract

**Status:** contract locked, implementation pending.

## Goal

Extend the existing kill-switch so it can kill a malicious process **automatically** for
high-confidence triggers (ransomware, YARA-matched malware, known-bad file hashes) without waiting
for a human to click Approve — while keeping the guard rails that stop it from ever killing
sshd/systemd/dockerd or firing on unattributed processes.

The infrastructure already exists (`internal/respond/killswitch.go` — `killWorthy` decision,
`RecommendKill(auto bool)` interface). Only the decision, the policy toggle, and the guard rails
need to be added.

## Trigger classification

| Trigger | Confidence | Behaviour |
|---|---|---|
| YARA rule match on FIM content (v2.5+) | high (community-verified rules) | **auto-approvable** |
| Ransomware entropy detection (`file_encrypted`) | high (byte-level signal on fresh files) | **auto-approvable** |
| File-hash reputation ≥ 10 vendor flags (VT) | high | **auto-approvable** |
| Suspicious-process heuristic, generic "malware" label | medium | recommend-only |
| Sigma rule fire without process attribution | low (no PID target) | not kill-eligible |

An auto-kill is only issued when **all three** hold:
1. The trigger sits in the auto-approvable set above.
2. The alert carries an attributed PID + process start-time (auditd/who-data — no attribution = no
   kill target).
3. The target passes every guard rail below.

## Guard rails (non-negotiable)

- **PID ≤ 100 is never auto-killed.** Kernel threads, init, systemd, early-boot daemons live below
  that watermark on every Linux distro DeusWatch runs on.
- **Process whitelist** — a default list of names never auto-killed:
  `systemd`, `init`, `sshd`, `dockerd`, `containerd`, `postgres`, `mysqld`, `nginx`, `apache2`,
  `nats-server`, `deuswatch-agent`, `deuswatch-worker`, `deuswatch-api`, `deuswatch-gateway`.
  Admin-editable via `KILL_WHITELIST` env (comma-separated) or the Response page (`manage_settings`).
- **Attribution mandatory.** The kill-switch already requires PID + procName + procStart; auto
  additionally requires `procStart != ""` (start-time is the anti-PID-reuse token).
- **Rate limit** per agent: max **3 auto-kills / minute**, hard cap. Beyond that, the trigger
  degrades to recommend-only and a "kill_rate_limited" alert fires so the operator sees the burst.
- **Fail-closed on missing config.** `KILL_AUTO_APPROVE` defaults to `0`. If the policy row is
  unreadable, the engine falls back to recommend-only. Never fail-open on this control.

## Policy config

Two overlapping toggles (mirroring the ban engine, so operators find them familiar):

- Env `KILL_AUTO_APPROVE=1` on the worker — forces on regardless of DB policy (declarative deploy,
  survives DB rewrites).
- DB `kill_policy` row (new table) — has `auto_approve boolean`, `whitelist text[]`,
  `rate_limit_per_min integer`. Managed via UI (Response page → new "Kill policy" editor, gated by
  `manage_settings`). Env, when set to 1, wins.

## Data model

New migration `000057_kill_policy.up.sql`:

```sql
CREATE TABLE IF NOT EXISTS kill_policy (
    id                  smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),  -- singleton row
    auto_approve        boolean  NOT NULL DEFAULT false,
    whitelist           text[]   NOT NULL DEFAULT ARRAY['systemd','init','sshd','dockerd',
                                                        'containerd','postgres','mysqld','nginx',
                                                        'apache2','nats-server','deuswatch-agent',
                                                        'deuswatch-worker','deuswatch-api',
                                                        'deuswatch-gateway'],
    rate_limit_per_min  integer  NOT NULL DEFAULT 3,
    updated_at          timestamptz NOT NULL DEFAULT now()
);
INSERT INTO kill_policy (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
```

Add columns to existing `agent_file_actions` — none needed; `decided_by = 'auto:<trigger>'` already
distinguishes auto from manual (existing free-text column).

## API + UI

- `GET /api/kill-policy` (view_dashboard) — read the current policy.
- `PUT /api/kill-policy` (manage_settings) — replace it (validates whitelist non-empty, rate limit
  between 1–60).
- **Response page** — a new "Kill policy" card next to the existing "Ban policy" editor. Same shape:
  auto-approve toggle + rate-limit stepper + whitelist textarea (one process per line) + "Save".

## Audit

Every auto-kill records:
- `decided_by = 'auto:yara' | 'auto:ransomware' | 'auto:filehash'` (the concrete trigger).
- Standard `agent_file_actions` row with `action='kill_process'`, target PID/proc/start.
- Notification path unchanged: severity ≥ notify threshold → Telegram/webhook/email fires.

## Tests

Unit tests in `internal/respond/killswitch_test.go`:

- `TestAutoApproveOnYARAMatch` — event with `dw_label=yara_malicious` + attributed PID → auto=true.
- `TestAutoApproveOnRansomware` — `action=file_encrypted` + attribution → auto=true.
- `TestAutoApproveOnKnownBadHash` — `dw_filehash_verdict=known_bad` + attribution → auto=true.
- `TestAutoApproveOffWithoutAttribution` — YARA match but empty `procStart` → recommend-only.
- `TestWhitelistBlocksAutoKill` — YARA match against `sshd` PID → recommend-only + log.
- `TestPIDUnder100NeverAutoKilled` — target PID = 42 → recommend-only + log.
- `TestRateLimitDegradesToRecommend` — 4th auto-kill in 60s → recommend-only + rate-limit alert.
- `TestPolicyDefaultsFailClosed` — no policy row → auto disabled.

Store test `internal/respond/kill_policy_test.go` — Load/Save round trip + validation errors.

## Rollout

- Migration is additive (new table, no ALTERs on existing tables).
- Default `auto_approve=false` — existing behaviour unchanged for operators who don't opt in.
- Docs update: `docs/kill-switch-demo.md` gets an "Auto mode" section explaining the trade-offs and
  how to enable safely (fill whitelist first, verify attribution on a test host, then flip the
  toggle).

## Estimated size

~300 lines Go across engine + store + API + UI + tests, one migration, one docs update. One commit,
one release (patch or minor — user's call).
