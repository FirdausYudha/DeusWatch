# ADR 0001 - Sigma Detection Engine Strategy

- Status: **Accepted** (Hybrid D); the aggregation path is implemented in-Go (see Addendum)
- Date: 2026-06-13 (addendum 2026-06-14)
- Context: design doc section 3 (choosing Sigma), section 6 (Phase 1 rule subset), section 10 (dry-run against history)

## Context & problem

DeusWatch's core value depends on Sigma: thousands of community rules + MITRE ATT&CK tags
"for free". The spike question: **how do we evaluate Sigma rules in DeusWatch?** Today
detection is just a single *hardcoded* brute-force detector.

## Research findings

1. **In-process match engine (Go).** `markuskont/go-sigma-rule-engine` (+ active 2025
   forks: runreveal, tufosa) - ~3000 lines, per-event Matcher-tree evaluation.
   Suited to **single-event** rules. Does **not** handle correlation/aggregation.
2. **pySigma (SigmaHQ, Python).** The gold standard; it *compiles* Sigma → a backend query
   (Elasticsearch, Splunk, **SQLite**). The SQLite backend (DenizenB/SigmaHQ) is used by
   **Zircolite** for pure SQL-based Sigma detection. It supports aggregation via SQL.
3. **The key insight - the real cost isn't the match engine, it's FIELD MAPPING.**
   Community rules are written for specific schemas (Sysmon/Windows Event/specific products).
   Applying them to our normalized data needs a "processing pipeline" (field taxonomy) -
   exactly what the pySigma pipeline solves, and what the Go match engine does NOT provide.
   Our prototype (`internal/detect/sigma`) confirms: parsing + conditions + modifiers are
   easy; aligning rule fields ↔ DCS is the real, ongoing work.
4. **SSH brute force is an AGGREGATION rule** (`count() by source.ip > N`) - which is why
   we were forced to write a stateful detector. A single-event match engine cannot replace
   it; aggregation needs state or SQL.

## Prototype results (`internal/detect/sigma`)

The subset evaluator (~300 lines) proves feasibility: it parses real Sigma YAML rules,
matches against DCS events (via `FlattenEvent` to dotted ECS keys), supports the
`contains/startswith/endswith/re` modifiers & `and/or/not`/`N of them` conditions, and
extracts MITRE from tags. Aggregation conditions are deliberately **rejected** and routed
to the SQL path. All covered by tests.

## Options

| Option | Contents | Pros | Cons |
|---|---|---|---|
| A. Adopt a Go fork | use runreveal/go-sigma-rule-engine | no reinvention, mature for single-event | no aggregation; still needs field mapping |
| B. Write our own evaluator | like this prototype | full control, zero deps | violates "don't reinvent"; maintenance burden |
| C. pySigma → SQL | compile rules to SQL, run periodically on TimescaleDB | aggregation & history dry-run "for free"; mature | Python at build time; latency = interval; SQLite dialect ≠ Postgres needs adapting |
| D. **Hybrid (recommended)** | A for real-time single-event + C for aggregation/dry-run | covers both design-doc needs | two paths to maintain |

## Proposed decision - Hybrid (D)

1. **Real-time single-event**: adopt a mature Go fork (evaluate `runreveal/
   go-sigma-rule-engine`); our prototype becomes a fallback/learning artifact, not the product.
2. **Aggregation & history dry-run** (section 10): a Zircolite-style SQL path - compile
   aggregation rules via pySigma (offline/CI, not runtime) into queries run periodically
   against the `events` hypertable. The current brute-force detector is a placeholder for this path.
3. **Primary investment** goes into the **DCS processing pipeline** (field mapping + curating
   rules relevant to the Phase 1 dataset: sshd/auth/web), because that is where the real cost
   & value lie - not in the match engine.

## Consequences

- Python (pySigma) enters as a **build/CI** dependency, not a runtime one - staying aligned
  with the single-binary Go runtime architecture.
- We need to define & maintain the DCS field taxonomy as a Sigma "pipeline".
- The brute-force detector stays in use until the SQL aggregation path is ready.

## Next steps if approved

1. A small spike: run one aggregation rule via pySigma→SQL against TimescaleDB.
2. Evaluate the chosen Go fork with 10-20 real single-event community rules + the DCS pipeline.
3. Decide the rule storage structure (`rules/sigma/`) + loader + versioning (section 10).

## Addendum (2026-06-14) - aggregation path implementation

The aggregation path (decision point 2) is **implemented in-Go at runtime**, not pySigma
at build time. Reason: to keep the single binary without a Python dependency, and the
Phase 1 aggregation scope (`count() [by field] <op> N` + `timeframe`) is narrow enough to
compile ourselves reliably.

- `internal/detect/sigma/aggregate.go`: `ParseAggRule` + `CompileSQL` - compiles an
  aggregation Sigma rule into a single parameterized query against the `events` hypertable.
  Selections compile to `WHERE` fragments (the `fieldColumns` map = the SQL mirror of
  `FlattenEvent`); literal values **always** go through arguments (anti-injection).
- `internal/detect/aggregate.go`: `AggregateRunner` runs rules periodically (in the worker,
  default every 30s), with a per-(rule, group) cooldown, plus `DryRun` for history testing
  (design doc section 10).
- The hardcoded brute-force detector now has a Sigma-rule equivalent
  (`rules/sigma/agg/ssh_bruteforce.yml`) - still running alongside; retiring the old
  detector happens once the SQL path is proven in production.

The rest of the decision still holds: real-time single-event still uses the interim
`internal/detect/sigma` evaluator (adopting a mature Go fork is not yet done); pySigma
remains an option for converting complex community rules going forward.
