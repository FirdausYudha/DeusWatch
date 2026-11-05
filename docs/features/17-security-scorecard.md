# 17. Security Scorecard

A one-page report card of the security program: eight indicators, each given a predicate
(**Effective / Adequate / Needs Improvement**) against a fixed threshold, grouped by **NIST CSF**
function, plus one overall predicate.

It exists because the Dashboard answers "what is happening right now" but not "how are we doing
over time". A director or CISO wants a small, honest set of numbers - how much is covered, how fast
we detect and respond, how clean our configuration is - not a live event stream. This page is that
summary.

**Read is `view_dashboard`.** The three writes gate higher and are written to the audit log:
importing the controlled-test log and setting a manual figure need `manage_settings`; flagging an
alert as a false positive needs `ack_alert`.

## The eight indicators

Grouped by CSF function, each with a fixed threshold band (seeded in `scorecard_thresholds`,
migration `000086`). Display labels and units live in code (`indicatorDisplay` in
`internal/store/scorecard.go`), not in the DB, so the UI language never depends on a seed having
run. Higher-is-better bands use `>=`;
lower-is-better bands use `<=`, inclusive on the better side.

| CSF | Indicator | Source (live) | Effective | Adequate |
|-----|-----------|---------------|-----------|----------|
| Identify | Active data-source coverage | online agents / registered agents | ≥ 95% | ≥ 80% |
| Protect | CIS benchmark score | `agent_benchmarks` (passed / evaluable, per host, averaged) | ≥ 80% | ≥ 60% |
| Detect | Scenario detection rate | `scenario_runs` (scenarios detected on **all** repetitions / 13) | ≥ 90% | ≥ 75% |
| Detect | MTTD (median time to detect) | live alerts: median(`ingested_at` − `time`) | ≤ 5 min | ≤ 15 min |
| Detect | False-positive ratio | `alert_reviews` (flagged FP / reviewed) | ≤ 10% | ≤ 25% |
| Detect | Bridging-failure detection (S11) | `scenario_runs` S11 reps alerting within 5 min | ≥ 90% | ≥ 75% |
| Respond | MTTR (median time to respond) | ticket queue: median(`acked_at` − `created_at`) | ≤ 15 min | ≤ 60 min |
| Govern | Report preparation time | latest manual figure (`scorecard_inputs`) | ≤ 1 day | ≤ 3 days |

Two figures are shown **without** a predicate: **attack frequency** (labeled alerts in the window)
and **IPs blocked** (distinct IPs in `containment_actions`).

### Predicate and overall

Each indicator maps to a score - Effective 3, Adequate 2, Needs Improvement 1. The overall
predicate is the mean of the computed scores: `>= 2.50` Effective, `>= 1.75` Adequate, else Needs
Improvement. An indicator with **no data** (e.g. no tickets yet, no CIS run yet) is reported as
`no data yet`, shown without a predicate, and **left out of the mean** - "we never measured this"
is not the same as "we measured zero", and collapsing them would quietly drag the card down. The
page shows how many indicators were counted, e.g. *5 of 8*.

The band logic is a pure function (`predicateFor`, `overallPredicate` in
`internal/store/scorecard.go`) and is unit-tested at every boundary.

## Where the numbers come from

The scorecard reads **operational data**, not a static snapshot:

- **MTTD** - the gap between when activity happened (`events.time`, the agent's clock) and when
  DeusWatch recorded the alert (`events.ingested_at`, migration `000087`). Rows before that column
  existed are excluded.
- **MTTR** - the real ticket queue: time from a ticket being created (≈ alert time) to being
  acknowledged (someone started handling it). A recommendation still awaiting approval has no
  ticket ack and is not counted.
- **CIS benchmark score** - `agent_benchmarks`, which every agent populates because the `sca`
  source is now a **default** on each newly enrolled agent and runs once a day (`scaInterval`,
  `internal/agent/sca_system.go`). Existing agents need an `sca` source added by config push.
- **Coverage** - online vs registered agents. A future source-registry (`data_sources`) would make
  this per log-source rather than per agent; the code carries a `shortcut:` comment to that effect.

### Detection rate, bridging and the scenario log

Detection rate and bridging-failure detection read `scenario_runs` - a log of controlled-test
scenarios. You load it on this page: paste the scenario CSV into **Import scenario log**. Rows are
keyed by `(scenario, repetition)`, so re-importing updates in place rather than duplicating, and a
malformed row is rejected with its line number instead of silently dropped. The importer accepts
both English (`scenario_id,repetition,…,detected,note`) and the original Indonesian column names.

> A scenario counts as detected only when **every** recorded repetition detected it; the
> denominator is always the full 13, so a scenario with no rows counts as not detected.

## Marking false positives

Any alert can be flagged true/false positive (`POST /api/alert-reviews`, `ack_alert`). The
false-positive-ratio indicator is `flagged FP / reviewed * 100`, and the note shows how many
alerts were reviewed - a 0% ratio over 2 reviews is a different statement from 0% over 200.

## In the periodic report

The scorecard is appended to the **[Report](04-report.md)** (both the Markdown export and the LLM
summary prompt): one line per indicator plus the overall predicate, so the scheduled report carries
the report card, not just raw counts. See `internal/report/report.go`.

## How to use it

1. Open **Security Scorecard** in the sidebar (any `view_dashboard` user).
2. Pick a window (7 / 30 / 90 days).
3. To populate detection rate / MTTD / bridging from a controlled test, **Import scenario log**.
4. Enter the **report preparation time** (days) under manual input for the Govern indicator.
5. Mark false positives from the alert workflow to populate the false-positive ratio.
6. CIS and MTTR fill in on their own as benchmarks run and tickets are handled.

## Ports / tech / variables

- **Tech**: Go (API + store + report), React/TypeScript page (`web/src/scorecard/Scorecard.tsx`).
- **Ports**: none of its own - the page talks to the API over HTTP like every other menu.
- **Endpoints**: `GET /api/scorecard?days=N`, `POST /api/scorecard/import`,
  `POST /api/scorecard/inputs`, `POST /api/alert-reviews`.
- **Thresholds**: seeded in migration `000086` and tunable by editing
  `scorecard_thresholds` (no edit screen yet; per-tenant editable thresholds are future work).
- **CIS scan interval**: `scaInterval` (24h default) in `internal/agent/sca_system.go`.

## Honest limits

- MTTD/MTTR/benchmark/false-positive read live data, so a fresh deployment shows `no data yet`
  until alerts, tickets, CIS runs and reviews accrue - that is correct, not an error.
- Detection rate and bridging still come from an **imported** controlled-test log. Turning that
  into a scheduled self-test (BAS-style) that re-runs scenarios and auto-fills `scenario_runs` is
  the natural next step toward a fully live scorecard.
- A number without freshness is a vanity metric; read each indicator's note for what it is based on.
