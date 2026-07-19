# DeusWatch — UI/UX Design Brief

> **Purpose of this file.** A complete, accurate inventory of every feature in the DeusWatch web
> app, written as a brief for a UI/UX revamp (e.g. in Claude Design). Design against *this* — it
> reflects what the product actually does today, so mockups map onto real functionality and can be
> wired up afterwards without inventing backend work.
>
> Current release: **v1.18.0**. Stack: React 19 + Vite + **Tailwind v4**, dark-only, no component
> library, served by nginx, talking to a Go API at `/api`.

---

## 1. The product in one paragraph

DeusWatch is a **self-hosted, all-in-one security platform**: SIEM + IDS/IPS ingest + lightweight
SOAR + threat intel (CTI) + optional LLM analysis. Logs arrive from cross-platform Go agents,
Wazuh/Suricata sensors, syslog devices, OpenSearch clusters, or an HTTP webhook; they're normalized,
detected against Sigma rules, MITRE ATT&CK-labelled, enriched with threat intel, scored, and
optionally acted upon (ban an IP, isolate a host, quarantine a file, revert a file). It replaces
five products for a small team that can't afford five products.

---

## 2. Users & jobs-to-be-done

| Persona | What they do here | What they need from the UI |
|---|---|---|
| **SOC analyst** (daily driver) | triage alerts, approve/dismiss bans, work tickets | speed, density, "what changed & what do I do next" |
| **Blue-teamer / IR** | investigate an incident, diff a changed file, quarantine evidence, revert after ransomware | forensic detail, timelines, safe destructive actions |
| **Admin / engineer** | enroll agents, write rules & decoders, wire integrations, tune scoring | powerful config without footguns |
| **Manager / owner** | read the report, see posture at a glance | clarity, executive summary, printable output |

Most sessions are **long-lived on a wall monitor** or a laptop in a dim room → dark theme is the
default and should stay excellent; light theme is optional, not required.

---

## 3. Non-negotiable design principles

1. **Honesty above polish.** The UI must never claim an action the system did not perform. Example
   that already exists: when nothing is wired to enforce a ban, blocked IPs are labelled
   **"Dangerous IP"**, not "Blocked", with an explicit banner explaining it. Keep this pattern —
   design explicit "recommended / pending / executed / failed" states, never a fake success.
2. **Density with hierarchy.** This is a data tool. Don't trade information away for whitespace —
   instead earn density with typographic hierarchy, alignment and restrained colour.
3. **Colour = meaning, never decoration.** Severity/band/status colours carry semantics (§5). A
   redesign may change the palette but must keep one colour = one meaning.
4. **Destructive actions are deliberate.** Ban, isolate, quarantine, revert, revoke, delete —
   always confirm, always say exactly what will happen and to what.
5. **Permission-aware.** Controls the user can't use should be hidden or clearly disabled, never a
   button that 403s.
6. **Every feature links to its docs.** A small "See documentation ↗" link next to a feature is an
   established pattern (`DocLink`); keep a place for it in the design.
7. **Fast perceived load.** Panels poll (5–15 s); design skeleton/stale-while-revalidate states so
   the screen never "flashes empty".

---

## 4. Technical constraints (must respect)

- **Tailwind v4 utility classes only** — no MUI/AntD/shadcn dependency. Custom components are fine.
- **Dark-first.** Current base: `slate-950/900/800` surfaces, `slate-700` borders, `slate-200/400/500`
  text, `indigo-500` primary. A new palette is welcome but must stay CSS-variable/utility friendly.
- **No icon library today** — nav uses unicode glyphs (`▣ ◈ ◰ ▦ ▤ ⌘ ⋔ ☰ ⧉ ◉ ⚙`). Introducing an
  inline SVG icon set is welcome (must be self-hosted, no CDN).
- **Charts are hand-rolled SVG** (no chart lib). Keep them simple to re-implement.
- **Responsive**: must work 1280→1920 desktop; tablet is nice-to-have; phone is not a priority.
- **Self-hosted / offline**: no external fonts, images, analytics or CDNs. Everything bundled.

---

## 5. Design vocabulary (semantics the design must express)

**Severity** (0–4, drives most colour): `Info · Low · Medium · High · Critical`.

**Threat band** (composite IP score 0–100): `low (<25) · medium (25–49) · high (50–74) · critical (≥75)`.

**Response action status**: `recommended → approved → executed` · `dismissed` · `unbanned` · `failed`.

**Containment status**: `recommended → contained → released` · `dismissed` · `failed`.

**Agent health**: `online · degraded · disconnected · stale · revoked` (+ never-connected).

**Entity types** (response decision table): `external_ip → block` (auto) · `host → network_containment`
(auto) · `user → alert` (alert-only) · `hash → alert` (alert-only).

**FIM change actions**: `created · modified · deleted · restored · **encrypted**` (ransomware signal)
· `quarantined`. **`authorized_change`** = a change during a trusted admin session (low, audit-only).

**LLM verdict**: `benign · suspicious · malicious` (+ not-analyzed).

**File-hash reputation**: `known_good · known_bad · unknown`.

**Snapshot storage**: `agent` (content on host) · `manager` (content on server, ransomware-safe).

Existing accent colours (semantic anchors): indigo `#6366f1` primary/selected, emerald `#10b981`
good/executed, rose `#f43f5e` critical/danger, amber `#f59e0b` pending/warning, sky `#38bdf8`
info/manager, violet `#8b5cf6`, orange `#fb923c`.

---

## 6. Global shell

- **Left sidebar** (fixed): brand, nav list, user block at the bottom (username, role, logout).
  Nav items are **permission-gated**:

  | Item | Permission |
  |---|---|
  | Dashboard | `view_dashboard` |
  | Response | `approve_remediation` |
  | Tickets | `view_tickets` |
  | Report | `view_dashboard` |
  | Agents | `view_dashboard` |
  | Rules · Decoders · Playbooks | `manage_rules` |
  | Integrations | `manage_integrations` |
  | Users | `manage_users` |
  | Settings | `manage_settings` |

- **Login** — username + password, **TOTP 2FA** second step, lockout messaging after repeated
  failures, optional self-registration (usually disabled).
- **Support modal** — help/about entry point.
- **Modals** are used heavily (wizards, editors, viewers). Design one consistent modal system:
  header + scrollable body (max ~90vh) + sticky footer actions.
- **Toast/inline feedback**: today it's inline coloured text (rose = error, emerald = success).
  A proper toast/inline-banner system is welcome.

---

## 7. Page-by-page feature inventory

### 7.1 Dashboard — *situational awareness + search*
- **Customisable widget grid**: drag-and-drop reorder, add/remove, per-widget **title, colour, wide/narrow**, persisted per user. Range selector (e.g. 24h/7d/30d).
- **Widget kinds & sources** (kind is constrained per source):
  - `stat`: Total events · Total alerts · Alerts 24h
  - `line`: Events over time
  - `bar | donut | table`: Severity breakdown · Top source IPs · Top rules · Top MITRE techniques
  - `donut`: LLM verdicts
  - `map | bar | donut | table`: Attack origins (country)
  - `risk`: **Top risky IPs** — IP + composite score + band
  - `watch`: **Suspicious IPs** — low-and-slow recon watchlist (fan-out/failure/spread score)
- **Database size / storage usage** indicator.
- **Searchable events & alerts table** — the analyst's main surface. Filters: free text, source IP, agent, rule, MITRE technique, category, min severity, alerts-only, from/to. Row detail includes: time, severity, rule, source IP + **geo**, agent/host, user, MITRE technique/tactic, label, **threat score + band**, CTI (AbuseIPDB confidence, OTX pulses), **LLM verdict + summary**, file path/hash + **hash reputation**, **file diff**, who-data (process/PID/user), HTTP method/URI/status/host, remediation action.
- **Empty/first-run**: no events yet → point to agent enrollment.

### 7.2 Response — *the SOAR surface*
- **Enforcement honesty banner**: if nothing can actually enforce a ban, say so and relabel rows "Dangerous IP" + link to firewall docs.
- Two views: **By IP** (offenders aggregated: IP, count, pending, score/band, actions) and **Events** (individual actions).
- Per-row actions: **Approve · Dismiss · Unban**, bulk select + bulk approve/dismiss/unban, dismiss-all-pending-for-IP. Status badges (recommended/approved/executed/dismissed/unbanned/failed) + progressive ban duration (10m → 30m → 1h → 24h → permanent).
- **Network containment panel**: contained hosts (agent, host, IP, reason, status, expiry), approve/dismiss/release, "auto" badge.
- **Decision table panel** (read-only): entity_type → action → enforcement (auto/engine or alert-only) + rationale.
- **Ban policy editor**: progressive durations, window, auto-approve.
- **IP whitelist editor**: trusted IPs/CIDRs (never banned; also powers the trusted-session gate).
- **Blocklist feed panel**: token for external firewalls to pull the active ban list (Palo Alto EDL/OPNsense/pfSense), regenerate token.

### 7.3 Agents — *fleet + endpoint forensics*
- **Agent list**: name, OS, status (online/degraded/disconnected/stale/revoked), last seen, config version, self-reported health detail.
- **Enroll wizard**: generate a one-time token → **one-line installer** command (per OS/arch) to copy.
- **Monitoring config editor** (per agent, pushed centrally; bumps config version): rows of sources — `dataset`, `type` (file/journald/wineventlog/fim), `path`, `interval` for poll types. For **fim** sources an extra row: **Snapshots** mode (`baseline only | on every change | scheduled | both`), **Store** (`on agent | on manager` — choosing *manager* pops a confirmation that content leaves the host), **Keep** (retention count).
- **Snapshots viewer** (per agent) — *the forensic centrepiece*:
  - Left: list of watched files that have versions (path + version count).
  - Right: **dated version timeline** — captured time, trigger (`on_change/scheduled/manual`), **storage badge** (agent/manager), size, SHA-256.
  - Per version: **"old vs new"** expandable **unified diff** (green additions / red deletions).
  - Per version: **Restore this version** (one click, confirm; current content is snapshotted first).
  - Per file: **Snapshot now** · **Quarantine infected/old file** (moves the current file to the agent's read-only quarantine dir for blue-team analysis).
  - **Ransomware recovery bar**: pick a date/time → **"Restore all files to this time"** (point-in-time bulk revert).
  - **Recent actions** list with outcomes (e.g. `quarantined to /var/lib/deuswatch/quarantine/...`).
- **Uninstall helper** (commands) and **Revoke** (kills the agent's certificate; agent self-uninstalls).

### 7.4 Rules — *detection content*
- Rule list with enable/disable, severity/level, MITRE tags, category; search.
- Rule editor (Sigma YAML) incl. single-event and **aggregation** rules (`count() by field > N` within a timeframe) and the DeusWatch `mitigation_action` extension (authorizes **network containment**).
- **Rule-pack marketplace**: bundled packs (install with no network) + **online feed** packs (install/update from a catalog). Install / Update / Uninstall states. Honest note: only Sigma-format packs are one-click; other engines (OWASP CRS, ET Open, YARA) are "run the sensor, DeusWatch ingests".

### 7.5 Decoders — custom, data-driven log decoders (regex → DCS fields), live-reloaded; test/preview against a sample line.

### 7.6 Playbooks — catalog of remediation playbooks stamped onto alerts per label (what an analyst should do).

### 7.7 Integrations — *connector catalog*, grouped by category, with encrypted secrets (write-only, masked):
- **CTI**: AbuseIPDB, AlienVault OTX (+ per-connector cache window)
- **FIM reputation**: VirusTotal, **MalwareBazaar**, CIRCL hashlookup, endpoint file quarantine
- **Firewall / bouncer**: MikroTik (multi-router sync), CrowdSec LAPI, agent nftables
- **LLM**: Ollama / OpenAI-compatible / Anthropic + **"Use for"** (triage / report / both)
- **Ingest**: Wazuh webhook, OpenSearch/Elasticsearch pull
- **Export**: webhook JSON
Each type has a form (fields, optional/secret, help text), enable/disable, and a docs link.

### 7.8 Tickets — Tier-2 DFIR case management (TheHive/IRIS-style): create from an alert, status/assignee/severity, notes/timeline.

### 7.9 Report — *the management artefact*
- Period selector **and explicit from–to date range**.
- Sections: totals, top rules/IPs/techniques, severity mix, **suspicious IPs**, agent health.
- **AI executive summary**: generate on demand, or scheduled (interval + **pinned hour of day**), with a custom prompt; the summary names the real date range.
- **PDF download** and Markdown/JSON output; scheduled delivery to notification channels.

### 7.10 Users — RBAC: users, roles, granular permissions matrix, create/edit/disable, password policy, per-user 2FA state, append-only audit log.

### 7.11 Settings
- **Account**: change password, **TOTP 2FA** enrol (QR) / disable.
- **Threat-scoring weights** (collapsible): composite score weights (abuse, fired-times, OTX, severity, **ML anomaly**) + suspicion weights (fan-out, failure ratio, spread, volume) shown as **normalised shares**, plus **scoring windows** (composite / suspicious). Live-applied.
- **Log storage lifecycle**: retention days, compress-after days, current DB size.
- **Notifications**: min severity, throttle, scheduled report delivery.
- **Log subscriptions (API)** — the sellable rich-log product: create a subscriber (name, scopes `events`/`indicators`, min severity) → **API key shown once**; list with usage (`request_count`, `last_used_at`), enable/disable, revoke.
- **Config profile**: export/import all settings (clone one server onto another).
- **Software update check** (read-only; never executes an update).

---

## 8. Cross-cutting states to design

For **every** table/panel: `loading (skeleton)` · `empty (with the one action that fixes it)` ·
`error (inline, retryable)` · `permission-denied (hidden or explained)` · `stale/refreshing`.

Special honest states worth designing explicitly:
- **"Nothing enforces this yet"** (Response) — action recorded but not executed.
- **"Recommend-only"** — containment/ban awaiting analyst approval.
- **"Alert-only"** — decision table entries with no automated enforcement.
- **"Not verified live"** — features implemented but not yet proven in this deployment.
- **"Manager vs agent storage"** — where a snapshot's content actually lives.

---

## 9. Flows worth designing end-to-end

1. **Triage**: alert appears → open detail → see who/what/where + score + LLM verdict → act (ban / contain / ticket / dismiss).
2. **Ransomware response**: encryption burst alert → host isolated (or recommended) → open Snapshots → pick a pre-attack time → **bulk revert** → quarantine a sample for the blue team.
3. **File forensics**: watched file changed → who-data (process/user) → **old vs new diff** → restore that version.
4. **Onboard an endpoint**: enroll wizard → one-line install → agent appears → push monitoring config.
5. **Sell/share logs**: create a subscription key → copy once → subscriber pulls events.

---

## 10. What I'd like from the redesign

- A **cohesive visual system**: palette (keeping the semantics in §5), type scale, spacing, elevation, border/radius language, icon set.
- **Component library sketches**: sidebar, page header, stat card, chart card, data table (sortable/filterable, bulk-select), badge/pill set (severity, band, status), modal, form controls, empty/loading/error states, confirmation dialog for destructive actions, inline banner (honesty notices), timeline/diff viewer.
- **High-fidelity mockups** for at least: Dashboard, Response, the **Snapshots viewer** (timeline + diff + actions), Agents, Integrations, Report, Settings.
- Keep it **dark-first**, dense, and fast — an operator tool, not a marketing page.

---

## 11. Wiring notes (for when the design lands)

- Keep the page decomposition above; I'll map components 1:1 onto the existing React files
  (`web/src/<area>/<Area>.tsx`) and the existing API helpers in `web/src/lib/api.ts`.
- Data shapes and endpoint names are already fixed by the Go API — the design can rename **labels**
  freely but the **fields** listed above are what's actually available.
- Anything that needs a *new* backend field is a separate decision — flag it in the design notes
  rather than assuming it exists.
- Tailwind v4 only; no new runtime dependencies without discussion (self-hosted/offline constraint).
