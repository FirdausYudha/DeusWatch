# DeusWatch Sigma rules

This folder contains detection rules in **Sigma** format, loaded by the worker at start
(`RULES_DIR`, default `rules/sigma`). The worker evaluates every normalized event against
these rules, alongside the built-in brute-force detector.

> Engine status: a subset evaluator (`internal/detect/sigma`) as an **interim** behind
> the `detect.Detector` interface - see [ADR 0001](../../docs/adr/0001-sigma-detection-engine.md).

## Field taxonomy (mapping pipeline)

DeusWatch events use **ECS** naming (see DCS, design doc section 7). Write rules using
these dotted ECS keys:

| Rule field | Example | Origin |
|---|---|---|
| `event.dataset` | `sshd` | log source |
| `event.action` | `ssh_login` | action |
| `event.outcome` | `success` / `failure` | outcome |
| `source.ip`, `source.port` | `203.0.113.10` | source |
| `user.name` | `root` | target account |
| `process.name`, `process.command_line` | | endpoint (Phase 2+) |
| `event.original` | raw log line | used by **keyword** rules |

**Aliases** for community-rule compatibility (resolved automatically,
case-insensitive - see `internal/detect/sigma/mapping.go`):
`User`/`username`→`user.name`, `src_ip`/`SourceIp`→`source.ip`,
`CommandLine`→`process.command_line`, `Image`→`process.name`,
`Computer`/`hostname`→`host.name`. Add an entry when adopting a new rule.

## Supported detection forms

- **Field match**: `selection: { field: value }` or `field: [a, b]` (OR).
  Modifiers: `|contains`, `|startswith`, `|endswith`, `|re`.
- **Keyword**: `selection: [ 'string1', 'string2' ]` → substring match against the event
  content (mainly `event.original`). Suitable for Linux log-message rules.
- **Condition**: `and` / `or` / `not`, parentheses, `N of them`, `all of <prefix>*`.

## AGGREGATION rules (SQL path)

Rules with a piped condition - `selection | count() [by <field>] <op> N` - cannot be
answered by a single event; they are **compiled to SQL** and run periodically by the worker
against the `events` hypertable (Zircolite/pySigma model, [ADR 0001](../../docs/adr/0001-sigma-detection-engine.md)).
This replaces the hardcoded brute-force detector with a Sigma-formatted rule.

- Put them in the `rules/sigma/agg/` sub-folder (loaded recursively one level deep; they can
  also live at the root - single-event vs aggregation is split automatically by the presence of `|`).
- **Supported pipe**: `count()` with an optional `by <field>`, operators `> >= < <=`.
- **`timeframe`** (e.g. `1m`, `5m`, `1h`, `1d`) = time window; default 5m.
- **Left of the pipe**: a boolean expression over selections (`and`/`or`/`not`/parens +
  selection names). `N of them` is **not** supported on the left of the pipe.
- Every field used must have a mapped DCS column (`fieldColumns` in
  `internal/detect/sigma/aggregate.go` - the SQL mirror of `FlattenEvent`). Literal values
  always go through parameterized arguments (anti-injection).
- Each group crossing the threshold fires one alert; there is a **cooldown** per (rule, group)
  so a long attack doesn't flood alerts. A **dry-run** against history is also available
  (`AggregateRunner.DryRun`).

## Automatic MITRE & severity

`tags: [attack.tXXXX, attack.<tactic>]` → `threat.technique.id` + `threat.tactic.name`.
`level:` (informational/low/medium/high/critical) → `event.severity` (0-4).

## Current rules

| File | Detection | Form |
|---|---|---|
| `ssh_login_root.yml` | successful SSH login as root (T1078.003) | field match |
| `ssh_breakin_attempt.yml` | sshd "POSSIBLE BREAK-IN ATTEMPT" message (T1595) | keyword |
| `sshd_invalid_user.yml` | login attempt for an unknown user (T1110.003) | keyword |
| `sshd_failed_root.yml` | failed SSH targeting root (T1110) | field match (multi-selection) |
| `fim_file_change.yml` | monitored FIM file modified/deleted (T1565.001/T1070.004) | field match (multi-selection) |
| `agg/ssh_bruteforce.yml` | brute force: >5 failures/IP per 1m (T1110) | **aggregation (SQL)** |
| `agg/ssh_invalid_user_burst.yml` | >10 "invalid user"/IP per 5m (T1110.003) | **aggregation (SQL)** |

## Generated rule packs

The bulk of the ruleset is **generated** from curated corpuses by
[`tools/rulegen/generate.py`](../../tools/rulegen/generate.py) into one-level subfolders
(the loader recurses exactly one level, so these are picked up automatically):

| Folder | Focus | Form |
|---|---|---|
| `judi/` | online-gambling ("judi online") content indicators: leetspeak core terms (`gacor`/`g4c0rr`/…), themed keyword corpuses (slot, togel, casino, bola, deposit, promo…), togel pasaran, slot titles/providers, and site-brand tokens | keyword |
| `deface/` | web-defacement banner strings + known webshell file names + double-extension upload patterns | keyword / `file.path` |
| `fim/` | File Integrity Monitoring on sensitive Linux/Windows/web-root paths | `file.path` + action gate |
| `endpoint/` | suspicious process/command lines: reverse shells, LOLBins, credential access, discovery, persistence, privesc | `process.command_line` |
| `agg/` | extra aggregation rules (auth-failure bursts, mass FIM change, web/firewall floods) | **aggregation (SQL)** |

Total ≈ 1000+ rules. Regenerate deterministically (stable `uuid5` ids) after editing a
corpus:

```
python tools/rulegen/generate.py     # (re)writes judi/ deface/ fim/ endpoint/ + agg/ packs
go run ./tools/rulelint rules/sigma   # validates EVERY file through the real engine (CI gate)
```

**Why keyword rules are broad here:** `matchKeywords` substring-matches
(case-insensitively) against *all* string fields of the event, not just `event.original`
— so one gambling-keyword rule fires whether the term lands in a web access-log line
(`event.original`), a dropped/injected file name (`file.path` from FIM), or a command
line (`process.command_line`). See `haystack()` in `internal/detect/sigma/sigma.go`.

> **Runtime cost:** every event is evaluated against every single-event rule linearly, and
> each keyword rule rebuilds the event haystack. ~1000 rules is fine for a prototype; if
> the hot path shows up in profiling, cache the haystack per event and/or index keywords.
> The `endpoint/` `process.command_line` rules only fire once endpoint process-event
> collection is shipping (Phase 2+); they are valid and forward-looking until then.
