# 12. Playbooks

Remediation playbooks (design doc §9): each detection label maps to the ordered steps an
analyst should take. The worker stamps the matching playbook onto **every fired alert**
before it is stored - deterministic, <1ms, no API cost, fully auditable - and the
recommendation appears on the alert's expanded detail in Events ("Recommended playbook").

## How it works

- A playbook = `label` + `name` + `steps[]`. The **label** is the alert's
  `deuswatch.label`: `bruteforce` and `selfhealth` are special; Sigma alerts are labeled
  by their **MITRE tactic** (`credential_access`, `initial_access`, `persistence`,
  `defense_evasion`, ...), so one playbook covers a whole tactic.
- The worker keeps a live catalog of the **enabled** playbooks and annotates alerts on
  every path (single-event, aggregation, pre-labeled/Suricata, selfhealth). The playbook
  never overwrites a recommendation that is already present (e.g. from the LLM).
- Stored on the alert as `deuswatch.remediation.action` (numbered steps),
  `source=playbook`, `status=recommended` - queryable like any other field.
- **11 builtin playbooks** are seeded from `rules/playbooks/` on first start and kept in
  sync on upgrades (new bundled labels appear; operator edits are never overwritten).

## How to use

1. **Playbooks** menu (requires `manage_rules`): browse the catalog, **Edit** the steps to
   match your runbook (e.g. add your escalation contact), **Disable** ones you don't want,
   or **Add playbook** for a custom label. Changes apply live (~30s), no restart.
2. Open any alert on the Dashboard (click the row) - the **Recommended playbook** block
   shows the steps right above the full JSON log.

## Endpoints & storage

| What | Where |
|---|---|
| CRUD | `GET/POST /api/playbooks`, `PUT/DELETE /api/playbooks/{id}` (permission `manage_rules`) |
| Table | `playbooks` (migration `000028`); one playbook per label |
| Bundled catalog | `rules/playbooks/*.yml` (`PLAYBOOKS_DIR`, default `/rules/playbooks`) |
| On the alert | `dw_remediation_action` / `dw_remediation_source` / `dw_remediation_status` columns |
