# 11. Decoders

Data-driven log parsing - the DeusWatch equivalent of Wazuh decoders. A decoder supports a **new
log source without writing code**: a regex extracts fields from a dataset's raw lines, and rules
scoped to the category you set then fire on it.

> New here? The end-to-end walkthrough (agent source -> decoder -> test -> rule -> ban) is in
> [docs/new-log-source.md](../new-log-source.md).

## How it works

- A decoder is a **Go RE2 regex** with **named capture groups** (`?P<source_ip>...`) that map to
  DCS fields, plus a static `category` / `action` / `outcome` / `level`. The full raw line is
  always kept as `event.original`, so keyword rules still work.
- Decoders run in the **gateway**, only as a **fallback** for datasets with no built-in decoder
  (sshd, web, firewall, fim, windows, suricata are built in). They are **compiled once and
  indexed by dataset**, so a line only tries the decoders for its own dataset - one linear-time
  regex per line (RE2 is ReDoS-safe).
- Stored in the `decoders` table, **seeded from the bundled `decoders/`** on first start; the
  gateway **live-reloads** the enabled set (~30s), so UI edits apply without a restart.

## How to use

- **Decoders** menu → table (name, dataset, category, regex, status). Toggle / Edit / Delete.
- **Add**: set the agent source **dataset**, a **category** (so rules can scope to it), and the
  **regex**. Named groups: `source_ip`, `source_port`, `destination_ip`, `destination_port`,
  `user_name`, `host_name`, `process_name`, `process_command_line`, `file_path`.
- **Test against real log lines** (the answer to "how do I know my raw lines?"):
  1. **Load recent lines** for the dataset - pulls real `event.original` samples from your own
     ingested logs.
  2. Click a line (or paste one) → **Test** shows whether it matched and **which fields** were
     extracted. Iterate on the regex before saving.
- Then add a rule under **Rules** scoped to that category, point an agent at the log (a source
  whose `dataset` matches), and the decoder + rule work together.

## Endpoints & source

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/decoders` / `POST /api/decoders` | list / create | `manage_rules` |
| `PUT /api/decoders/{id}` / `DELETE /api/decoders/{id}` | edit-toggle / delete | `manage_rules` |
| `GET /api/decoders/samples?dataset=` | recent raw lines for a dataset | `manage_rules` |
| `POST /api/decoders/test` | try a regex on one line, see extracted fields | `manage_rules` |

Frontend: [`web/src/decoders/`](../../web/src/decoders/). Backend:
[`internal/decoders/`](../../internal/decoders/), engine
[`internal/ingest/decoder.go`](../../internal/ingest/decoder.go). Bundled seeds +
format: [`decoders/`](../../decoders/README.md).

## Ports / tech

- Browser → Web `9173` → API `9080`. The **gateway** applies decoders during normalization.
  Language: Go (RE2), React/TypeScript (UI). Stored in PostgreSQL.

## Variables

- `DECODERS_DIR` (gateway/api env, default `/decoders`) - where the bundled seed decoders live
  (baked into the image). Everything else is DB-backed and edited live in the UI.

## Converting Wazuh decoders (optional, local)

`tools/wazuh2decoder` converts Wazuh XML decoders into **draft** DeusWatch decoders (translating
os_regex to RE2). Output is gitignored (Wazuh is GPLv2) and every draft must be reviewed and
**tested** here before enabling. See [`tools/wazuh2decoder/`](../../tools/wazuh2decoder/README.md).
