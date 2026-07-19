# DeusWatch - Progress & Handoff

> Progress notes for continuing on another machine. Design source of truth: [DeusWatch.md](DeusWatch.md).
> Last updated: 2026-07-18 (v1.16.0).

**FIM versioned snapshots — Phase 1 done 2026-07-19 (ADR 0002, on `main`, unreleased).** Manager-
side foundation of dated snapshots + restore-by-date, fully verified locally: migration 000041
`fim_snapshots`; `internal/store/fimsnapshots.go` (RecordSnapshot w/ dedup, ListSnapshots timeline,
ListSnapshotPaths, PruneSnapshots — integration test passes on real PG); `agent.Source` snapshot_mode/
snapshot_storage/snapshot_retention (carried via config push, backward-compatible); API
`GET /api/fim/snapshots{,/paths}` (verified via curl); UI = snapshot Mode/Store/Keep selectors on FIM
sources + a read-only "Snapshots" timeline viewer on the Agents page. **Both storage (agent/manager)
and trigger (on_change/scheduled/both) are admin-configurable** per the user's directive. Phases 2-3
(agent capture + restore-by-date directive) need a live Linux agent — NOT built. Target v1.17.0.

**LIVE-VERIFIED 2026-07-18 (Phase D + decision table)** — brought up a real stack (Docker
Postgres+NATS, `api` via `go run`), applied migration 000040, and exercised the endpoints
end-to-end. ALL PASS: subscription create → one-time key (only hash stored); events feed honors
min_severity floor + the 30s settle lag (a MOVING window — a fresh event serves once it ages);
cursor pagination (limit=1) + has_more; auth 401 on bad/absent key; scope enforcement (events-only
key → indicators 403, events 200); indicators feed with min_score; usage counters (request_count +
last_used_at) increment; disable → 401, revoke → 401; `GET /api/response/decision-table` returns
the exact policy. **MalwareBazaar also LIVE-VERIFIED** (2026-07-18) against the real abuse.ch API
with the user's Auth-Key: a catalogued sample hash → known_bad ("MalwareBazaar sample (exe)"), a
bogus 64-zero hash → unknown.
**ClickHouse sink also LIVE-VERIFIED** (2026-07-19): real clickhouse-server:24.3 + worker with
CLICKHOUSE_URL + API webhook ingest — EnsureSchema auto-created `deuswatch.events` (MergeTree,
PARTITION BY toYYYYMM, ORDER BY (timestamp, source_ip)); sshd events flowed bus→sink→ClickHouse,
flattened correctly (source_ip / category=authentication / outcome=failure / severity), and an
analytics query returned top attacker IPs by failed-auth count. See [[honesty-principle]].

**v1.16.0 RELEASED 2026-07-18** — **Phase D: subscription API** (the LAST target-
architecture layer — A/B/C/D now all done). The sellable "rich-log" product: external subscribers
PULL enriched events + curated indicators over a token-authed HTTP API, each with a revocable
per-subscriber API key and usage accounting. migration 000040 `subscriptions` (stores only the
key sha256; plaintext shown once). `internal/store/subscriptions.go`: CRUD + AuthenticateSubscription
(hash lookup, bumps usage) + forward-only cursor-paginated `SubscriptionEvents` with a **settle
lag** (default 30s, `SUBSCRIPTION_SETTLE_LAG`) so enrichment lands before an event is served +
`SubscriptionIndicators`. Opaque `(time,id)` cursor = exact gap-free resumption. Subscriber
endpoints `GET /api/subscribe/{events,indicators}` (key via Bearer/X-API-Key/?key=, scope-checked);
admin CRUD `GET/POST /api/subscriptions`, `POST /{id}/toggle`, `DELETE /{id}` (manage_integrations).
UI: Settings → "Log subscriptions (API)" admin panel + See-documentation. docs/subscription-api.md.
Tests: key hashing, cursor round-trip/empty/malformed, scope sanitize. **Target-architecture
roadmap COMPLETE.** Remaining big-picture: verification gaps (Windows live-log, Suricata sensor),
Phase 7 (auditd/marketplace/Helm) per deuswatch-project-state.
https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.16.0

**v1.15.2 RELEASED 2026-07-18** — bundles five items (user asked to ship as a PATCH v1.15.2, not
1.16.0, to see the changes on their server). Target-architecture roadmap after this: **only
Phase D subscription API remains** (A/B/C done). https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.15.2
1. **Raw daily log archive (Phase B)** — `internal/archive`: every normalized event is also
   appended as a zstd frame to `<ARCHIVE_DIR>/<source>/<dataset>/<YYYY-MM-DD>.log.zst`, with
   retention sweep and path-traversal-safe segment names. docs/archive.md. (commit e1da72f)
2. **Naming cleanup** — removed the internal external-architecture project name and all
   non-English terms from public docs/code/migrations/progress.md; DeusWatch reads as its own
   full-English product. Standing rule saved. (commit 03dd756)
3. **MalwareBazaar hash reputation** — abuse.ch known-malware DB as a third FIM reputation
   source (after VirusTotal, CIRCL). A hit = always known-bad (raises the FIM event to High); a
   miss = unknown (never known-good). Free abuse.ch Auth-Key. Integrations catalog entry
   (`malwarebazaar`) + `MALWAREBAZAAR_API_KEY` env. (commit e1e6bac)
4. **Entity_type decision table** — `internal/respond/decision.go`: explicit single-source-of-
   truth policy the worker routes alerts by. `external_ip`→block (auto·ban engine), `host`→
   network_containment (auto·containment engine), `user`/`hash`→alert-only (surfaced, not auto-
   enforced). Behaviour-preserving refactor of `makeAlertHook`. `GET /api/response/decision-table`,
   read-only Response-page panel, docs/decision-table.md. (commit 02be81c)
5. **ClickHouse analytics sink (Phase C)** — `internal/clickhouse`: an optional secondary store
   for large-scale columnar analytics (TimescaleDB stays the operational source of truth). A
   consumer on `logs.normalized` flattens each event into a wide row and batch-inserts over the
   ClickHouse HTTP interface (`INSERT … FORMAT JSONEachRow`) — **no third-party driver**, works
   against any ClickHouse. Idempotent schema create (MergeTree, partition by month, ordered by
   (timestamp, source_ip), optional TTL). Failed batches requeue; ClickHouse being down never
   blocks ingestion. Off unless `CLICKHOUSE_URL` set. Env: CLICKHOUSE_URL/DATABASE/TABLE/USER/
   PASSWORD/BATCH/FLUSH/RETENTION_DAYS. docs/clickhouse.md. Tests: config, DDL, row flatten,
   httptest JSONEachRow insert + requeue-on-failure.
Also: "See documentation" links wired for MalwareBazaar (catalog Doc → features/07-integrations.md)
and ClickHouse (Agents page), per the standing see-docs rule.

**v1.15.1 RELEASED 2026-07-18** — **ML anomaly bridge** (external anomaly detection ↔ the scoring
core; Phase A of the target-architecture roadmap). `GET /api/ml/ip-features` (per-IP feature vectors:
contacts/distinct_uris/distinct_ports/distinct_hours/failures/span/avg_gap+stddev) + `POST
/api/ml/anomaly` (writeback 0-100 → `ip_anomaly` table, migration 000039). Composite scorer folds
`anomaly` via new `score.Weights.Anomaly` (DEFAULT 0 = opt-in, no silent change; raise in Settings
→ Threat-scoring weights → Anomaly (ML)). Token-authed `ML_API_TOKEN`. docs/ml-anomaly.md w/
Isolation Forest example. NOTE: user asked to release this feat as a PATCH (v1.15.1) not 1.16.0.
https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.15.1
Target-architecture phases remaining: B raw-zstd-archive, C ClickHouse sink, D subscription API,
small: MalwareBazaar + entity_type decision table.

**v1.15.0 RELEASED 2026-07-18** — (1) **BUG FIX**: the AI Executive Summary ignored the Report
date-range picker (always summarized last 24h). `reportSummaryGenerateHandler` now honors
`?from=&to=` (BuildReportRange) and the LLM prompt names the real dates. (2) **Scoring windows
UI-tunable**: `score_config` gained composite_window_secs / suspicious_window_secs (default from
SCORE_WINDOW/SUSPICIOUS_WINDOW env), worker reads them live each tick, Settings panel has the
inputs. This is the answer to "the score doughnut disappears on older alerts" (composite score is
a rolling window; raise it to keep the doughnut longer). https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.15.0
Open idea (not built): store the composite score ON the event at insert time so the doughnut is
PERMANENT per-alert (option 2 from that discussion) — user chose option 1 (bigger window) for now.

**v1.14.0 RELEASED 2026-07-18** — (1) **Suspicious-IP watchlist** (low-and-slow recon):
`internal/score.ComputeSuspicion` (CTI-independent: fan-out 0.40 + failure-ratio 0.30 + spread
0.20 + volume 0.10), `suspicious_ips` table (migration 000037), worker `runSuspiciousScorer`
(24h window / 5m), dashboard "watch" widget, fed to the AI report. Only external IPs
(RFC1918/loopback excluded). docs/suspicious-ips.md. (2) **UI-tunable scoring weights** for BOTH
scorers: migration 000038 `score_config` (single-row JSONB, overlaid on defaults), worker
re-reads weights each tick (live), API GET/PUT `/api/score-config`, Settings "Threat-scoring
weights" panel (normalized-share inputs + reset). https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.14.0

**v1.13.0 RELEASED 2026-07-18** — (1) **Native syslog input**: `internal/syslogin` (UDP+TCP
listener in the worker behind `SYSLOG_LISTEN=:5514`, off by default; RFC3164/5424 parser; program
TAG → dataset so the right decoder runs; TCP handles newline + octet-counting; sender shows as
`syslog/<host>`). docs/syslog.md. (2) **"Top risky IPs" widget**: new `risk` widget kind reading
the existing `TopIPScores` leaderboard (score + band), in the default dashboard layout.
https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.13.0
Also: gitignore now ignores stray root build binaries (/agent /worker /api /gateway) from
`go build ./cmd/...` without -o.

**v1.12.0 RELEASED 2026-07-17** — Report over an explicit from–to DATE RANGE (page + PDF +
Markdown). `store.BuildReportRange(from,to)` (all aggregates `time >= from AND time < to`);
`BuildReport(hours)` kept as the rolling wrapper so the scheduler/on-demand summaries are
unchanged. `report.Report.Until` (zero = rolling). `GET /api/report?from=&to=` (RFC3339 or
YYYY-MM-DD) wins over `?hours=`; a bare `to` date covers the WHOLE day (exclusive end = next
midnight). Tested: day boundary, RFC3339, from-without-to, swapped range.
https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.12.0

**v1.11.0 RELEASED 2026-07-17** — (1) **online rule-pack feed** (`packs/catalog.json` +
`internal/rules/remote.go`; `PACKS_FEED_URL`, "off" = no egress; InstallPack dispatches
bundled→feed; re-install = Update). (2) **"Dangerous IP"**: the Ban List no longer badges
"blocked" when nothing enforces it — new `GET /api/response/enforcement` (live push responder OR
pull blocklist feed). (3) **AI summary at a fixed hour**: migration 000036 `at_hour` (-1 = old
drifting interval, the default), pure+tested `reportDue()`, UI shows the SERVER's clock since
"08:00" is ambiguous on a UTC container. https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.11.0

**Answered without code (2026-07-17):** MikroTik multisync ALREADY pushes the FULL active
blocklist — `ActiveBlocks` returns every active block and `Sync` reconciles (add missing/remove
stale) every 10s, so pre-existing bans and rebooted routers are covered. An agent stuck at
"never connected" = never heartbeated (the Agents page already auto-refreshes every 15s); prime
suspect is `MANAGER_IP` unset before first start → gateway mTLS cert SAN lacks the IP → remote
agents fail TLS.

**v1.10.0 RELEASED 2026-07-17** — real-time FIM (fsnotify) + one-click Install for BUNDLED
curated rule packs (new `packs` package, first pack "WAF / Web attack essentials" pairing with
v1.9.0 WAF ingest) + UX fixes. https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.10.0
- **Field-taxonomy fix**: sigma `FlattenEvent` did not expose `http.*` / `rule.*` — WAF-keyed
  rules would install and never fire. Fixed; now you can write rules over v1.9.0 WAF events.
- **UX fix (user complaint)**: page filters reset on navigation → new `usePersistedState` hook
  (localStorage). Applied to dashboard range, Events severity/alertsOnly/limit, Rules filters.
  Free-text search deliberately stays transient. Rule packs section collapsed by default.
- **NEXT: rule-pack half "A"** = remote/auto-updating packs (fetch over HTTPS, same import path
  as InstallPack; needs manager egress). Honest constraint: only Sigma-format packs are
  installable — CRS/ET/YARA are other engines (run the sensor + ingest). See [[deuswatch-backlog]].

**v1.9.0 RELEASED 2026-07-17** — ModSecurity/OWASP CRS WAF ingestion: `normalizeModSecurity`
decoder + DCS HTTP field group (http.method/uri/status_code/host, migration 000035) + dashboard
"HTTP request" block + bundled `waf_block_burst.yml` agg rule (>10 blocks/IP/1m → alert → ban) +
docs/modsecurity.md. Sniffs any dataset label; requires [client] so noise lines are ignored;
CRS severity mapped conservatively. https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.9.0
NEXT: user to verify live with real OPNsense+ModSecurity logs. Core backlog #4 real-time FIM
(fsnotify) still pending. See memory [[deuswatch-backlog]].

**v1.8.0 RELEASED 2026-07-17** — Rule-pack marketplace on the Rules page (installed packs =
rule categories with real enable/disable + external catalog: SigmaHQ/ET/OWASP CRS/Sysmon-modular/
YARA/MITRE as link-outs) + more in-app "See documentation" links (Settings/Agents).
https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.8.0
Marketplace decision: lives in Rules (not Integrations). NEXT (WAF series): ModSecurity decoder +
HTTP field group (user has real OPNsense+ModSecurity logs to verify). Core backlog #4 real-time
FIM still pending. See memory [[deuswatch-backlog]].

**v1.7.0 + v1.7.1 RELEASED 2026-07-16** — Wazuh ingest webhook UI + OpenSearch/Elasticsearch pull +
native FIM who-data (Linux/auditd) + "See documentation" links + fixes. Applies migrations
000032–000034. v1.7.1 patch: who-data "Rule exists" survives restarts + alert carries process/diff.
Backlog work order (memory): #1 webhook UI ✅, #2 OpenSearch pull ✅, #3 who-data ✅, **#4 real-time
FIM (fsnotify) = NEXT.**

**LIVE-VERIFIED 2026-07-16 on the user's server:**
- ✅ **Ingest webhook** — POST returned `{"accepted":1}`, event appeared under `wazuh-agent/*`.
- ✅ **who-data** — a `sudo tee` defacement of /var/www/html/index.php was attributed to
  `user_name: deus(1001)` (auid = the LOGIN user behind sudo, not effective root). Proved
  audit→agent-correlation→normalize→store→display end-to-end. NOTE the "Rule exists" bug (v1.7.0)
  disabled who-data after a restart — the live test surfaced it → fixed in v1.7.1; quick recovery
  is `auditctl -W <dir> -p wa -k deuswatch_fim` then restart. process_name on the ALERT needs the
  v1.7.1 worker (raw file_modified event had it from v1.7.0).
- 🟡 **OpenSearch pull** — still needs a real ES/OpenSearch cluster to verify.

## Status summary

The security detection platform **runs end-to-end**, **Phases 1-6 complete** (see the
roadmap table in [README.md](README.md)): ingest → Sigma detection (single + aggregation)
→ CTI enrichment → progressive-ban response → LLM triage/report, plus the Phase 4 admin
layer (granular RBAC, Integrations registry, agent management + enrollment wizard, Tier-2
ticketing, drag-and-drop dashboard), the Phase 5 endpoint/ops layer (FIM hash reputation +
quarantine, webhook export, config profiles, provider-agnostic LLM incl. Ollama, scheduled
AI reports), and the Phase 6 detection-depth layer (custom decoders, Suricata/ET ingest,
~1000+ UI-managed rules, network containment, blocklist feed). The **entire codebase is in
English**. Stack: Go (agent/gateway/worker/api), PostgreSQL+TimescaleDB, NATS JetStream,
React+Vite+Tailwind.

> **Detection verified end-to-end on BOTH Linux and Windows** (2026-07-14, real hardware).
> Linux/sshd fully verified. **Windows: VERIFIED on real hardware** - the agent reads the
> live Security log (Windows Event Log; logs to `%ProgramData%\DeusWatch\agent.log`),
> normalizes 4625/4624/4740/4688/4104 by numeric EventID, and a remote SMB logon brute force
> (from an Ubuntu box) fired a *Windows Logon Brute Force* (T1110.001) alert carrying the
> attacker IP + the target agent (windows2) + host (Deus). A companion by-host rule catches
> local/console brute force with no source IP. The old "beta piece" (live Security-log read)
> is now proven. (macOS and mobile agents dropped.) **Still pending:** Suricata live sensor.

```
agent ──mTLS──▶ gateway ──▶ NATS ──▶ worker(enrich+detect) ──▶ TimescaleDB ──▶ API ──▶ Web UI
```

## Done & verified

| Area | Contents | Status |
|---|---|---|
| Foundation | monorepo, docker-compose (db/nats/api), cross-OS mTLS (CA+cert) | ✅ |
| DCS schema | `internal/ingest/schema.go` + TimescaleDB hypertable (chunk/day, compression, retention) | ✅ |
| Pipeline | `internal/bus` (NATS), `internal/store` (pgx), `internal/worker` | ✅ |
| Ingest | mTLS gateway + sshd normalization → DCS; agent tail → ship | ✅ |
| Detection | single-event Sigma (field/keyword/alias/MITRE) + **Sigma→SQL aggregation path** (compiles to a TimescaleDB query, periodic runner+cooldown+dry-run), `rules/sigma/` (+`agg/`) | ✅ |
| CTI enrichment | `internal/enrich` + Postgres TTL cache + **real AbuseIPDB/OTX clients + GeoIP** (ip-api) + configurable escalation + **community blocklist** | ✅ + shown in UI |
| **Response engine** (Phase 2) | `internal/respond`: nftables/CrowdSec/Mikrotik + dry-run + **progressive ban** + approval workflow (API) | ✅ |
| **Notifications** (Phase 2) | `internal/notify`: Telegram/email/webhook + dedup/throttle | ✅ |
| **LLM worker** (Phase 3) | `internal/llm`: triage alert→verdict (Claude SDK / heuristic) → `deuswatch.llm.*` | ✅ + UI |
| **Report** (Phase 3) | `internal/report` + `GET /api/report` (JSON/Markdown) | ✅ |
| Auth | login, sessions, **RBAC**, **append-only audit log**, user management, **TOTP 2FA** | ✅ + UI |
| Web UI | Login, Dashboard, **Agents**, **Integrations**, **Tickets**, Users, Settings, Response, Report | ✅ |
| Agent | per-agent enrollment, config push, heartbeat+offline buffer, **FIM**, **native Windows Service**, per-OS collectors, cross-compile | ✅ |
| Infra | **automatic migration runner** (embed), **CI** (vet/test/govulncheck/gosec/web), pinned images, gateway+worker in compose | ✅ |
| **Granular RBAC** (Phase 4) | per-user permission overrides on top of roles (`users.permissions`), checklist UI, menus gated by permission; catalog `internal/auth/rbac.go` | ✅ + UI |
| **Integrations** (Phase 4) | admin-managed registry (`internal/integrations`): MikroTik / CrowdSec / nftables-agent / AbuseIPDB / OTX; secrets AES-256-GCM encrypted at rest (`internal/secret`, `SECRETS_KEY`), write-only | ✅ + UI |
| **Agent mgmt** (Phase 4) | central monitoring config (sources + per-source scan `interval`), Wazuh-style OS/arch enrollment wizard | ✅ + UI |
| **Ticketing/DFIR** (Phase 4) | `internal/tickets`: open→in_progress→resolved→closed, assignee, case notes, time-to-resolve; "+ Ticket" from an alert | ✅ + UI |
| **Customizable dashboard** (Phase 4) | per-user widget layout (`user_dashboards`), `GET /api/dashboard` series + timeline; SVG widgets (stat/bar/donut/line/table/attack-map), edit mode with **drag-and-drop** reorder, type/color/size | ✅ + UI |
| **Hash reputation + quarantine** (Phase 5) | `internal/hashrep` (CIRCL + VirusTotal, TTL cache) wired into FIM; opt-in endpoint file **quarantine/delete** on known-bad hash | ✅ + UI |
| **Provider-agnostic LLM** (Phase 5) | Claude (official SDK) / **Ollama** / any OpenAI-compatible endpoint; per-integration "Use for" selector (triage / report / both); AI report summary **on-demand + scheduled** + PDF export + UI-editable prompt template | ✅ + UI |
| **Export & config profiles** (Phase 5) | JSON **webhook export** (events/alerts/report → SIEM/n8n/Zapier); **config-profile import/export** to clone a server; in-app **update check** (semver vs GitHub Releases) + `scripts/update.sh` | ✅ + UI |
| **Notifications v2** (Phase 5) | UI-configurable severity threshold + **scheduled report delivery** (Telegram/email/webhook); docs in [docs/notifications.md](docs/notifications.md) | ✅ + UI |
| **Storage ops** (Phase 5) | dashboard log-storage panel (DB size/budget, retention lifecycle, replication status), near-full alert, retention/compression editable from Settings; [docs/storage.md](docs/storage.md) | ✅ + UI |
| **UI-managed rules** (Phase 6) | rules **DB-backed, managed from the UI** (browse/edit/toggle/add/delete, validated on save, builtins seeded + auto-synced); **~1000+ rules** across `auth/ web-attack/ fim/ endpoint/ windows/ deface/ judi/ agg/` with category folders + filters + search | ✅ + UI |
| **Detection coverage** (Phase 6) | SSH + **sudo/su privesc**, **web attacks** (SQLi/traversal/LFI-RFI/scanner-UA/Shellshock/webshell; nginx access-log normalizer), **port scan** (T1046, firewall drops), **Windows** (4625/4624/4740 + 4688/4104 process & PowerShell LOLBins, account/group changes, 1102 audit-cleared), keyword-rule FP fixes (scoped to `event.original` + logsource) | ✅ (Linux e2e-tested; Windows server-side verified) |
| **Custom decoders** (Phase 6) | data-driven regex → fields for **new log sources without code**: DB-backed, UI editor + **tester on raw lines**, gateway live-reload; `wazuh2decoder` + `wazuh2sigma` converters in `tools/` | ✅ + UI |
| **Suricata / ET ingest** (Phase 6) | Suricata/Snort **EVE JSON alerts** as a first-class source (Emerging Threats Open/Pro); bans/containment apply; [docs/suricata.md](docs/suricata.md) | ✅ (needs a real sensor to verify live) |
| **Network containment** (Phase 6) | isolate a compromised host from the LAN (host self-isolation + edge block) when a rule authorizes it (e.g. **webshell-in-uploads → containment**); **trusted-session gate** suppresses file-change alerts correlated with a whitelisted admin/deploy login | ✅ + UI |
| **Blocklist feed** (Phase 6) | pull-model feed of active bans for **external firewalls** (Palo Alto EDL, OPNsense, pfSense, MikroTik) + UI panel (URL + token regenerate); [docs/blocklist-feed.md](docs/blocklist-feed.md) | ✅ + UI |
| **Self-monitoring** (§13) | worker health checker: agent states `online → degraded → disconnected → stale` (heartbeat carries self-reported health, e.g. buffer piling up); **disconnect raises a HIGH `selfhealth` alert** (T1562.001) through the normal pipeline; recovery logged as info; status badges in Agents UI; worker `/healthz` + `/readyz` (`WORKER_HTTP_ADDR`); envs `AGENT_DISCONNECT_AFTER`/`AGENT_STALE_AFTER`; migration 000027 | ✅ + UI |
| **Disk-watermark janitor** (§8) | at `STORAGE_JANITOR_PERCENT` (default 90) of `STORAGE_BUDGET_GB` the worker drops the OLDEST event chunks (max 6/run, newest never) until under the watermark + HIGH `selfhealth` alert per trigger; also fixed: `STORAGE_BUDGET_GB` was documented but never passed to containers in compose | ✅ |
| **Raw-log ingest webhook** | `POST /api/ingest/webhook?token=&agent=&dataset=&host=` (token-authed like the blocklist feed, `INGEST_WEBHOOK_TOKEN`) accepts raw log lines (newline text or JSON array) from external systems (e.g. a **Wazuh manager**) → `ingest.Normalize` (custom decoders apply) → NATS `logs.normalized` → normal pipeline; source tagged `wazuh-agent/<name>` on the dashboard; API now holds a NATS publisher + its own live decoder set; [docs/wazuh-webhook.md](docs/wazuh-webhook.md); unit-tested | ✅ |
| **Agent debuggability + idempotent install** | Windows agent now logs to `%ProgramData%\DeusWatch\agent.log` (SCM discards stderr - this is why the Windows path was invisible); wineventlog collector surfaces read errors (unauthorized = not SYSTEM) instead of failing silently; installers re-runnable (stop service + atomic binary replace - fixes the misleading `curl (23)` on Linux re-install and locked-.exe on Windows); agent uninstall/cleanup documented per-OS in [docs/features/05-agents.md](docs/features/05-agents.md) | ✅ |
| **Remediation playbooks** (§9) | per-label remediation steps stamped onto EVERY fired alert (`deuswatch.remediation.*`, now persisted to the events table) on all paths (single-event, aggregation, pre-labeled/Suricata, selfhealth); never overwrites an LLM recommendation; **11 builtin playbooks** in `rules/playbooks/` (bruteforce, MITRE tactics, selfhealth) seeded/synced to DB; **Playbooks UI menu** (browse/edit/enable/add, live-reload ~30s); "Recommended playbook" block on the alert detail; migration 000028; verified live vs Postgres | ✅ + UI |
| **Agent name re-use + cert serial pinning** | enrolling a REVOKED agent's name takes over its row (new cert, un-revoked, health reset; same id/config); the gateway now rejects by **CN + certificate serial**, so the superseded cert stays dead after re-use (revoked rows are deliberately never deleted - they ARE the kill switch for still-valid mTLS certs); active names stay taken; verified live against Postgres (`TestEnrollFlow`) | ✅ |
| **Production hardening** | login brute-force lockout (per IP+username, `LOGIN_MAX_FAILURES`/`LOGIN_LOCKOUT`, audit `login_locked`, 429 + Retry-After) + registration throttle; password policy (`PASSWORD_MIN_LEN` floor 8, common-list/username/repeat checks); proxy-aware `ClientIP` (`TRUSTED_PROXIES`, anti-spoof rightmost-untrusted XFF); db/NATS host ports bound to 127.0.0.1 (`DEUSWATCH_DB_BIND` for replication); container memory caps; `scripts/backup.sh/.ps1` + `restore.sh/.ps1` (TimescaleDB pre/post-restore flow); [docs/production.md](docs/production.md) (TLS via Caddy/nginx+certbot, port exposure, runbook) | ✅ |

All tests (unit + integration + e2e) pass; gosec & govulncheck clean. Sigma ADR: [docs/adr/0001-sigma-detection-engine.md](docs/adr/0001-sigma-detection-engine.md).

## Phase 4 notes (admin & UX)

- **Migrations 000007-000010**: `users.permissions text[]` (RBAC), `integrations`, `tickets`+`ticket_comments`, `user_dashboards`.
- **Permissions**: `view_dashboard, ack_alert, approve_remediation, execute_block, view_tickets, manage_tickets, manage_rules, manage_agents, manage_integrations, manage_users, manage_settings`. Roles: viewer=dashboard; analyst=+ack/approve/tickets; admin=all. NULL `users.permissions` = inherit role, non-NULL = explicit custom set. `GET /api/permissions` = catalog + role defaults; `PUT /api/users/{id}` updates role/perms.
- **Secrets**: `internal/secret` AES-256-GCM via `SECRETS_KEY` (base64 32 bytes); no key → DEV key + warning. Integration secret fields encrypted at rest, never returned (a `secrets_set` map flags which are set); blank-on-edit preserves them.
- **Integrations enforcement is wired** - the worker builds the CTI provider & MikroTik responder from the registry (`resolveCTIKeys`/`resolveResponder`, DB > env). Agent-side nftables auto-block: gateway `GET /v1/blocklist` (mTLS) serves the response engine's active blocks when an `nftables_agent` integration is enabled; the agent polls it (`AGENT_FIREWALL=nftables`) and applies to a local nft set (`internal/agent/firewall_linux.go`, root/CAP_NET_ADMIN; Linux only). Manager side verified over mTLS; nft application runs on a real Linux agent.
- **Agent intensity**: `agent.Source.Interval` (seconds) honoured by poll collectors (fim, wineventlog) via `Source.scanInterval`; file/journald stay live-streamed.
- **Dashboard**: drag a widget by its ⠿ grip (native HTML5 DnD) to reorder; layout persists per user. Free-form X/Y positioning + drag-to-resize would need `react-grid-layout` (not added).
- **Logo**: `web/public/deuswatch-eye.png` (resized) in sidebar + login; source art in `logo/`.

## Prerequisites on a new PC

- **Go 1.25+** (developed with 1.26)
- **Docker Desktop**
- **Node 22+** (for the web UI)

## Setup on a new PC - ONE COMMAND

```bash
git clone https://github.com/FirdausYudha/DeusWatch.git
cd DeusWatch
docker compose -f deploy/docker-compose.yml up -d --build
```

That's it. Compose brings up **everything**: db, nats, **certgen** (init: generates the
mTLS certificates into `deploy/certs`, idempotent), api (auto-migrate), gateway, worker, and **web** (nginx).

- **Web UI:** http://localhost:9173 · **API:** http://localhost:9080 (host ports configurable via `DEUSWATCH_*_PORT`)
- **Dev login:** `admin` / `thewatcher` (auto-seeded; change via `ADMIN_PASSWORD`).
- **Self-registration** is enabled on the login page (new account = viewer role). Disable with: `REGISTRATION_ENABLED=0`.

> Web dev hot-reload (optional): `cd web && npm install && npm run dev` → :5173 - do NOT
> run it alongside the `web` container (port clash); turn off one of them.
> Manual migrate if needed: `DATABASE_URL=... go run ./cmd/migrate`. Regen certs: `go run ./cmd/certgen --out deploy/certs -force`.

## Running the full pipeline (local agent)

gateway/worker are now **already in docker-compose** (step 1 starts them). Only the
**agent** runs on a separate endpoint. To run the binaries locally (dev), set the env
then run (PowerShell example in `bin/`):

```
NATS_URL=nats://localhost:4222
STORE_DSN=postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable
CERT_DIR=deploy/certs            # gateway/worker use the server cert + CA
RULES_DIR=rules/sigma
GATEWAY_ADDR=:8443

go build -o bin/gateway.exe ./cmd/gateway   # + worker, agent
# run gateway, worker, then agent (agent: GATEWAY_URL=https://localhost:8443)
```

Cross-compile the agent for all OSes: `./scripts/build-agent.sh` → `dist/`.
Install the agent: `deploy/agent/` (systemd `install-linux.sh`, Windows `install-windows.ps1`).

### Agent enrollment flow (Wazuh-style)
1. Admin creates a token: `POST /api/agents/tokens` (Bearer admin) → `{token}`.
2. Agent exchanges the token: `agent -enroll -token <T> -name <name> -manager http://host:8080 -out <certdir>`.
3. The agent runs normally with that cert; it shows up in `GET /api/agents`; it can be revoked.
4. Config push: admin `PUT /api/agents/{id}/config {sources:[...]}`; the agent fetches it via the gateway at start + poll (version increases → restart to apply).

## Important notes/gotchas

- **Automatic migrations** - in-house runner (`internal/migrate` + embed in the `migrations` package); the api applies them at start (idempotent). Standalone: `cmd/migrate`. `RUN_MIGRATIONS=0` to disable.
- **Pinned images**: timescaledb `2.17.2-pg16`, nats `2.10.22-alpine`. Changing the pin on an old volume created by a different version can clash - use a fresh volume.
- **CI**: `.github/workflows/ci.yml` (vet/build/test with pg+nats services, govulncheck, gosec, web tsc+build). gosec excludes rules inherent to the domain (see the workflow).
- **Response engine**: `RESPONDER=dryrun|nftables|crowdsec|mikrotik|none` (default dryrun). nftables/crowdsec/mikrotik are WRAPPED in dry-run unless `RESPONSE_LIVE=1`. `RESPONSE_AUTO_APPROVE=1` executes without approval. Approve/dismiss via `POST /api/responses/{id}/approve|dismiss`.
- **Notifications**: active when any channel is filled in - `TELEGRAM_BOT_TOKEN`+`TELEGRAM_CHAT_ID`, `WEBHOOK_URL`, or `SMTP_HOST`+`SMTP_FROM`+`SMTP_TO`(+`SMTP_USER`/`SMTP_PASS`). Threshold `NOTIFY_MIN_SEVERITY` (default high), dedup `NOTIFY_THROTTLE` (default 10m, per rule+IP). The worker calls it via `worker.AlertHook` (alongside the response engine).
- **LLM worker** (Phase 3): `ANTHROPIC_API_KEY` → Claude analyzer (model `ANTHROPIC_MODEL`, default `claude-opus-4-8`, via the official SDK); `LLM_ENABLED=1` → offline heuristic analyzer. The worker polls alerts without a verdict every 20s → fills `deuswatch.llm.*`.
- **Report**: `GET /api/report?hours=24` (JSON) or `?format=md` (Markdown) - a summary of events/alerts/severity/top IP/rule/MITRE/verdict.
- **Community blocklist**: `BLOCKLIST_URLS` (comma-separated IP/CIDR feeds) → matching IPs are marked abuse=100 (feed `blocklist`); refresh every `BLOCKLIST_REFRESH` (default 6h).
- **Real CTI enrichment**: set `ABUSEIPDB_API_KEY` / `OTX_API_KEY` / `GEOIP_ENABLED=1` in the worker env (without them a mock provider is used). Escalation thresholds: `ABUSE_ESCALATE_THRESHOLD` (default 90), `OTX_ESCALATE_THRESHOLD` (default 5).
- **bin/ & dist/ & deploy/certs/ are gitignored** - rebuild binaries & regen certs on a new PC.
- When changing service code, **rebuild the binaries** before a demo (some demo bugs were from stale binaries).
- `gateway` needs `STORE_DSN` for revocation/config-push/heartbeat (optional; without a DB those features are off).
- **Cross-host mTLS**: the agent trusts the manager by the private CA, not by hostname/IP (`mtls.ClientConfig` verifies the chain via `VerifyPeerCertificate`, no SAN name check), so agents on other hosts connect without per-IP cert tweaks. `MANAGER_IP` (deploy/.env) optionally pins the IP into the server-cert SAN. Regen certs + re-enrol agents when the CA changes. See README "Deploying agents".
- The `detect-worker` detector… the durable NATS consumer uses DeliverNew (no backlog replay).
- The single-event Sigma engine = an interim evaluator; the aggregation path = an in-Go compiler to SQL (ADR 0001 addendum).
- Changing the TimescaleDB image pin on an old volume created by a different version → clash (`$libdir`); use a fresh volume.

## Main roadmap (Phases 1-3) - DONE ✅

The following seven roadmap items are implemented, tested, and verified end-to-end:
Sigma aggregation→SQL+new rules (#4); FIM+native Windows Service+Agents page (#5);
real CTI clients+GeoIP+UI (#6); response engine+progressive ban (#7); infra migration/CI/
compose (#8); notifications (#9); LLM worker+report+blocklist (#10).

## Phase 4 (admin & UX) - DONE ✅

Full i18n (codebase → English); granular per-user RBAC; Integrations registry (encrypted
secrets); central agent monitoring config + OS/arch enrollment wizard; Tier-2 DFIR
ticketing; customizable drag-and-drop dashboard; eye logo wired in.

## Phase 5 (endpoint & ops) - DONE ✅

File-hash reputation (CIRCL/VirusTotal) + opt-in quarantine/delete on known-bad hash;
agent **self-uninstall on revoke**; provider-agnostic LLM (Ollama / OpenAI-compatible /
Claude) + AI report summary (on-demand + scheduled + PDF + editable prompt); JSON webhook
export; config-profile import/export; UI alert threshold + scheduled report delivery;
storage panel + UI retention control; configurable host ports (**9080/9443/9173**);
in-app update check (semver vs GitHub Releases) + `scripts/update.sh`; searchable
Events/Alerts; unban + free-text search + bulk actions in Response; CTI honesty fixes
(no fabricated intel, UI-managed cache TTL, live provider reload, OTX country fallback);
macOS/mobile agents dropped (focus Linux + Windows).

## Phase 6 (detection depth & extensibility) - DONE ✅

~1000+ DB-backed rules managed from the UI (categories: auth/web-attack/fim/endpoint/
windows/deface/judi/agg) + validation + builtin auto-sync; web access-log normalizer
(nginx) activating the web keyword rules; expanded Windows normalizer (process/PowerShell/
account/audit-cleared); sudo privesc + port-scan (T1046) rules; **custom decoders**
(DB-backed regex → fields, UI editor + tester, gateway live-reload) + `wazuh2decoder`/
`wazuh2sigma` converters; **Suricata/ET EVE JSON ingest**; **network containment** (host
isolation + edge block) + webshell-in-uploads containment rule + trusted-session gate;
**blocklist feed** for external firewalls (EDL/OPNsense/pfSense/MikroTik) + UI panel;
agent name surfaced across Events/Response/Report + full-JSON log view + agent filter;
FIM changed-path on alerts; per-menu feature docs (`docs/features/01-11`) + new-log-source
tutorial.

## Project principle: honesty (standing rule, 2026-07-13)

We are building an ambitious security app - **and every claim must be honest**. People
depend on a security product's claims for their actual security; an overclaimed
"verified" can mean an undetected incident on someone else's server. Concretely:

- **implemented ≠ verified.** ✅ = code done + auto-tested; "verified" = proven in real
  conditions. The README status badge, roadmap rows and coverage table use ✅/🟡 markers.
- A platform/feature is never marked verified until a live run proved it.
- Limitations and beta status go in prominent places, not fine print (this is already
  the project's DNA: CTI shows "-" instead of fabricated data; Windows agent labeled
  beta; WhatsApp channel documented with its real risks).
- Release notes state what was NOT verified when relevant.
- When an overclaim is caught, fix it immediately (precedent: README "Phase 1-6
  complete" → "implemented · Linux verified e2e").

## Versioning & release convention (decided 2026-07-13)

Semantic versioning `MAJOR.MINOR.PATCH`, applied from **v1.2.0 onwards** (the v1.1.x
line bumped patch for features - accepted as history, not repeated):

- **PATCH** (v1.2.0 → v1.2.1): bugfixes/docs/perf only - updating requires no reading.
- **MINOR** (v1.1.x → v1.2.0): new backward-compatible features (a work cycle like
  auditd, self-monitoring, playbooks, Windows-agent verified). Patch resets to 0.
- **MAJOR** (→ v2.0.0): breaking change only - agent protocol incompatibility (mass
  re-enroll), non-auto-migratable schema, renamed/removed env vars or API endpoints.
  Never bump major just because a feature feels big.
- **Borderline precedent (v1.2.1)**: a `feat:` commit that actually FIXES a defect in an
  existing workflow (no new feature surface to learn - e.g. revoked-name re-use + serial
  pinning) may ship as PATCH at the owner's discretion. Genuinely new capabilities always
  go MINOR.

**Release mechanics** (nothing in the code needs editing - the version comes from the
git tag): `git tag -a vX.Y.Z` → `git push origin vX.Y.Z` → publish a GitHub Release
from that tag (the in-app update check reads `releases/latest`; a tag alone is not
enough). `scripts/update.sh` bakes `git describe --tags` into the build.

**Automatic version bumping** (decided 2026-07-13): the release version is derived from
conventional-commit prefixes since the last tag - any `feat:` → MINOR bump; only
`fix:`/`refactor:`/`perf:` → PATCH; a breaking change (`!` suffix, e.g. `feat!:`, or
one flagged in review) → MAJOR, always raised explicitly with the owner first;
`docs:`/`chore:`-only → no release needed. The release is prepared (tag + generated
notes) and shown as a draft; publishing happens after the owner confirms.

## Next-step candidates (updated 2026-07-13)

**Verification gaps (highest value, no new code):**
- ~~Windows agent live Security-log read on real hardware~~ **DONE 2026-07-14** - verified
  live: agent reads the live Security log, remote SMB brute force fired a labeled alert with
  attacker IP + agent + host.
- **Suricata with a real sensor** - ingest path is code-complete; needs an eve.json from a
  live sensor to call it verified. (Now the only remaining verification gap.)

**Backlog ideas (captured 2026-07-14):**
- **Kafka bridge** as an alternative to NATS for enterprise scale (NATS stays the default
  for modest specs). Note it as an optional ingest/bus transport; design later.
- ~~**Wazuh webhook in the Integrations UI**~~ **DONE 2026-07-16.** Dedicated **inbound** panel
  on the Integrations page ("Log ingest webhook (Wazuh & others)") - NOT an Integrations-registry
  entry (those are outbound encrypted connectors). Token now stored in DB (migration 000032
  `ingest_webhook`, single-row like `blocklist_feed`), seeded once from `INGEST_WEBHOOK_TOKEN`
  env then UI-managed. `ingesthook.Handler` reads the token PER REQUEST (`TokenFunc`) so
  enable/regenerate/disable take effect with no restart; `NewStatic` kept for tests. API:
  `GET /api/ingest-config`, `POST /api/ingest-config/regenerate|disable` (PermManageIntegrations),
  fail-closed on lookup error. Store: `WebhookToken/SetWebhookToken/SeedWebhookTokenFromEnv`.
  Tests: dynamic-token accept/reject/rotate + fail-closed. UNRELEASED.

- ~~**OpenSearch/Elasticsearch pull**~~ **DONE 2026-07-16.** New `internal/espull` package tails
  an existing ES/OpenSearch index (headline use: the Wazuh indexer = OpenSearch → read
  `wazuh-alerts-*` directly, reusing `ingest.NormalizeWazuh`). Sort by timestamp asc + page with
  `search_after`, cursor persisted in `ingest_cursor` (migration 000033) keyed per integration so
  a restart resumes without replay/gap; first poll uses a 5m look-back. Modes: auto (Wazuh-or-raw)
  | wazuh | raw. Integrations catalog gained an `opensearch` type (category `ingest`, new UI badge);
  worker `runESPull` launches one poller goroutine per enabled integration, publishing to
  logs.normalized. Auth: basic or API key; insecure_tls for self-signed. Docs: docs/opensearch.md
  (with the honest timestamp-tailing limitation — late/duplicate-ts docs can be missed; webhook is
  lossless). Tests: Wazuh mapping + cursor advance + raw message extraction + resume-from-cursor
  (httptest ES mock). NOTE: integrations resolved at worker startup → adding one needs a worker
  restart (same as MikroTik). UNRELEASED.

- ~~**Native who-data**~~ **DONE 2026-07-16.** The DeusWatch agent now attributes each FIM change
  to the process/user that made it, via the Linux **audit** subsystem (same mechanism Wazuh uses).
  Opt-in `AGENT_WHODATA=1` (needs root + auditd; installs `auditctl -w <dir> -p wa -k deuswatch_fim`
  and tails /var/log/audit/audit.log, `AGENT_AUDIT_LOG` override). Portable audit-record parser
  (`internal/agent/whodata.go`, unit-tested: who/paths/hex/unset-auid/event-id) + linux watcher
  (`whodata_linux.go`, path→actor cache, 30s TTL, rotation-safe tail) + non-linux stub. FIMChange
  gained actor/actor_exe/actor_pid/user/syscall; `WithWhoData` on the scanner; normalizeFIM maps to
  DCS Process+User. **Persistence fix:** added `process_name`/`process_pid` columns (migration
  000034) to events + insert + query + EventRow — process who-data was DROPPED on insert before,
  so this also fixes the Wazuh syscheck who-data path. Dashboard File-change block shows
  "changed by <proc> (pid) as user <user> · who-data". Docs: docs/whodata.md (Linux-only + best-
  effort correlation limitations stated). UNRELEASED. **Next backlog item: real-time FIM (fsnotify).**
  See [[deuswatch-backlog]].
- Wazuh JSON normalizer DONE (maps rich Wazuh alert fields → DCS; MITRE tactic → label →
  playbook); could extend the group→category/label maps as more Wazuh rule types are seen.

**Superior FIM roadmap (captured 2026-07-15) - the differentiator vs Wazuh.** DeusWatch's
FIM is Go, so a lean cross-platform (Linux/Windows/macOS) real-time engine is feasible.
Current: agent poll + SHA-256 baseline + created/modified/deleted + ~150 Sigma rules +
hash reputation + who-data (only when fed from Wazuh). Four features to go BEYOND Wazuh:
  1. **Real-time** via fsnotify - DONE 2026-07-17. `internal/agent/fimwatch.go` watches the FIM
     roots (recursive dirs + on-the-fly new subdirs) and fires a debounced (500ms) trigger →
     immediate `Scan()`; interval polling stays as a safety net (min 1m when real-time is on).
     Cross-platform (inotify / ReadDirectoryChangesW / kqueue via fsnotify v1.10.1). Graceful
     fallback to poll-only on watcher error or `FIM_REALTIME=0`. Scan() is still the source of
     truth, so a missed/duplicate event only affects latency. Tests: fires on file create+modify
     and on files in a newly-created subdir. UNRELEASED.
  2. **Content diff** - DONE 2026-07-15. Agent snapshots small text files (≤256 KiB, no
     NUL bytes) in the FIM baseline; on modify it computes a line LCS diff → `file.diff` →
     migration 000029 `file_diff` column → shown in the alert detail (amber block, +green/
     -red lines). Verified live (defacement diff stored + rendered). Binaries/large files:
     hash only, no diff. This snapshot also feeds feature 4 (restore).
  3. **YARA scan on changed files** - catch UNKNOWN webshells by pattern, not just known
     hashes (libyara via cgo, or a Go subset). Complements hash reputation.
  4. **Auto-restore / rollback** - DONE 2026-07-15 (manual/one-click). Agent persists each
     watched text file's original known-good copy to disk (`fim-snapshots/`, written on
     first sight, never auto-overwritten, survives restart). Manager: `file_restores` table
     (migration 000031) + gateway `GET /v1/restore` per-agent one-shot feed + API
     `POST /api/fim/restore` (execute_block perm) + a **Restore file** button on the FIM
     alert detail. Agent polls every 15s, writes the snapshot back atomically, emits a
     `file_restored` event. NEVER writes without an explicit request (safe default).
     `FIM_SNAPSHOTS=0` disables. Auto-restore-per-directory remains a later opt-in.
     Verified: snapshot ensure/restore, scanner persistence, restore request flow (dedup +
     per-agent + one-shot) live vs Postgres.
  - Native who-data on DeusWatch's OWN agent (Linux fanotify FAN_REPORT_PIDFD / audit / eBPF)
    is the hard, ambitious differentiator; today who-data comes only via the Wazuh feed.

**MikroTik multi-endpoint sync - CrowdSec-bouncer-like - DONE 2026-07-15.** Implemented:
`Syncer` optional interface; `MikrotikResponder.Sync` reconciles the router's managed
address-list to `ActiveBlocks` (adds missing, removes stale, only touches comment=`deuswatch`
entries - manual entries safe); `MultiResponder` fans Block/Unblock/Sync to ALL configured
MikroTik routers; `resolveResponder` builds from ALL enabled mikrotik integrations (not just
`rows[0]`); `runBlocklistSync` loop reconciles every `RESPONSE_SYNC_INTERVAL` (default 10s).
Needs `RESPONSE_LIVE=1`. Verified with an httptest RouterOS mock (reconcile, idempotent,
manual-entry-safe, multi-router fan-out). Pull model (`GET /api/blocklist`) still available.

**MikroTik push VERIFIED LIVE on real hardware (2026-07-16)** ✅ - over a WireGuard tunnel
(hub `10.10.10.1` → RouterOS `10.10.10.8`), REST `200`, bans reach `deuswatch_ban`. Debugging
this surfaced three silent-failure traps, now fixed on OUR side:
  1. `RESPONSE_LIVE` unset → responder wrapped in dry-run → `runBlocklistSync` returns silently,
     nothing pushed, no clear reason. Fix: worker now logs an explicit `NOTE - MikroTik is
     configured but RESPONSE_LIVE!=1` warning; `RESPONSE_LIVE`/`RESPONSE_AUTO_APPROVE`/
     `RESPONSE_SYNC_INTERVAL` are now documented in `.env.example` (were missing entirely).
  2. No connectivity feedback → added `MikrotikResponder.Verify(ctx)` (read-only GET) run per
     router at worker startup: logs `REST check OK (list=… reachable)` or `REST check FAILED: …`
     with the distinguishing cause (unreachable/TLS vs `HTTP 401` vs list). Would have caught the
     `www-ssl address=` reset and the empty-list case immediately.
  3. Real-hardware gotchas (`www-ssl address=` must allow the HUB not the router's own IP; list
     name must match the filter rule; Docker needs `MASQUERADE -o wg0`) → full **Troubleshooting**
     table added to `docs/mikrotik.md` §4 + table.

**v1.6.0 RELEASED 2026-07-16** - FIM one-click restore (part 2) + MikroTik health-check/
insecure_tls/troubleshooting docs. https://github.com/FirdausYudha/DeusWatch/releases/tag/v1.6.0
NEXT VERIFICATION STEP (server): `./update.sh` on the manager, update the agent on a
FIM-monitored host, then the defacement test: modify a monitored file → dashboard shows the
FIM event + line diff → click **Restore** → file reverts + a `restored` event appears.
Only after that passes may Superior FIM be marked ✅ verified (currently 🟡 implemented).

**Advanced composite scoring - DONE 2026-07-15.** `internal/score` weighted formula
(fired_times + AbuseIPDB + OTX + worst severity → 0-100 + band, `DefaultWeights` abuse .40 /
fired .30 / otx .15 / sev .15, count caps); `ip_scores` table (migration 000030);
`RefreshIPScores` runs the per-IP windowed aggregate SQL + upserts + prunes; worker
`runIPScorer` every `SCORE_INTERVAL` (30s) over `SCORE_WINDOW` (10m); API `AttachScores`
adds threat_score/threat_band per Events/Alerts row; UI shows a small colored **doughnut**
(higher=redder) replacing the raw abuse/otx badges. **Scenario ban**: `SCENARIO_BAN_SCORE>0`
auto-recommends a ban when an IP crosses that score (synthesizes an event so whitelist +
dedup + progressive ban apply); off by default. Suricata/WAF weights fold into MaxSeverity
later. Verified live vs Postgres (12 fires + abuse 100 + otx 8 → score 75 critical).

**Native syslog input (captured 2026-07-15).** For the "everything funnels to a collector"
network model (OPNsense / OpenWAF / ET Pro → Unraid syslog): add a UDP/TCP :514 syslog
listener (gateway or a small receiver) so devices forward directly, decoders parse. Today
the same is possible via a DeusWatch agent tailing the syslog file on Unraid. NOTE: ET Pro's
packet-level completeness comes from ET Pro's paid DPI - DeusWatch consumes those alerts
(Suricata eve.json already native), it is not a DPI engine itself.

**OpenSearch pull/ingest (captured 2026-07-15).** Optionally pull logs FROM an OpenSearch/
Wazuh-indexer database (query the index periodically → normalize → pipeline), as an
alternative to the push webhook. Complements the existing Wazuh push-webhook.

**Phase 7 (per README roadmap):**
- Linux **process audit** (auditd/execve) - biggest detection blind spot on Linux (no
  process visibility; Windows already has 4688/4104).
- Rule/integration **marketplace**; **Helm chart** for Kubernetes deploys.

**Production hardening - DONE 2026-07-13** (login lockout, password policy, TLS recipe,
backup/restore scripts, loopback-bound internal ports, memory caps - see the Done table
and [docs/production.md](docs/production.md)).

**Design-doc audit 2026-07-13 (DeusWatch.md goals not yet built - candidates, not debt):**
- ~~Remediation **playbooks** (§9)~~ **DONE 2026-07-13** (catalog + worker stamping + UI
  menu - see the Done table).
- ~~**Self-monitoring** (§13)~~ **DONE 2026-07-13** (agent states + disconnect alert +
  worker healthz - see the Done table). Still open from §13: internal pipeline monitor
  (NATS consumer lag / ingest-vs-write rate) and a dedicated System Health page.
- ~~**Disk-watermark janitor** (§8)~~ **DONE 2026-07-13** (see the Done table).
- Cold archive to MinIO/S3 Parquet (§8, optional); ntfy/Gotify + WhatsApp-gateway channels +
  per-channel routing/quiet hours (§11); agent self-update w/ cosign verification (§12);
  Windows Firewall as a *ban* enforcer (§10, currently isolation-only); ML anomaly baseline +
  pgvector RAG (§6 Phase 3).
- Deliberately dropped (not debt): Android + macOS agents. Scheduled (Phase 7): marketplace, Helm, auditd.

**Smaller refinements (carried over):**
- Real-time FIM via fsnotify (currently polling); canary config deploy.
- Per-agent block scoping (gateway filters blocklist by `agent_scope` + CN).
- Dashboard: `react-grid-layout` free-form X/Y + resize; real geographic world map widget.
- Mature Sigma Go fork for the single-event engine.
- pgvector for RAG/LLM (embedding column already in the schema).

## Commit map (newest → oldest, partial)

```
feat(detect): aggregation alerts carry attacked agent/host + Windows by-host rule + NULL-group fix
feat(agents): in-UI Uninstall helper + Windows service file logging + idempotent installers
feat(ingest): raw-log webhook (Wazuh -> DeusWatch) + agent logging/install fixes
feat(playbooks): per-label remediation playbooks - catalog, worker stamping, UI editor
feat(enroll): revoked-name re-use + gateway cert serial pinning
feat(selfhealth): agent health states + disconnect alert + disk janitor + worker healthz
feat(security): production hardening - login lockout, password policy, backups, TLS docs
feat(response): blocklist feed (external firewalls, pull model) + UI panel
docs: per-menu feature modules + new-log-source tutorial
feat(decoders): DB-backed custom decoders + UI editor/tester + live-reload + converters
feat(rules): Windows/process/PowerShell + sudo privesc + SSH/web-attack rule sets
feat(ingest): Suricata/Snort EVE JSON (ET Open/Pro) as a log source
feat(respond): network containment + trusted-session gate + webshell containment rule
feat(ui): agent name across Events/Response/Report + full-JSON view + agent filter
feat(detect): web access-log normalizer (nginx) - activates ~772 web keyword rules
feat(rules): ~1000 rules (judi/deface/FIM/endpoint) + category folders + UI filters
feat(report): AI summary - custom prompt template, schedule, PDF; Ollama guide
feat(update): semver update check vs GitHub Releases + update.sh
feat(storage): log-storage dashboard panel + UI retention/compression control
feat(detect): Windows EventID normalizer + brute-force/lockout; port-scan T1046
feat(response): unban + search + bulk actions; CTI live-reload + honest enrichment
feat(notify): UI severity threshold + scheduled report delivery
feat(config): profile export/import; webhook export (JSON)
feat(fim): hash reputation (CIRCL/VirusTotal) + quarantine; agent self-uninstall
feat(llm): Ollama / OpenAI-compatible providers
feat(deploy): configurable host ports (9080/9443/9173) + wizard auto-detect
feat(dashboard): drag-and-drop widget reordering
feat(dashboard): customizable Kibana-style widget dashboard
feat(tickets): Tier-2 DFIR ticketing + logo
feat(agents): central monitoring config + OS/arch enrollment wizard
feat(integrations): admin-managed connector registry
feat(rbac): per-user granular permissions (checklist)
i18n: translate entire codebase to English (UI, Go, SQL, rules, docs)
(#10) feat(llm): LLM worker + report + community blocklist (Phase 3)
(#9)  feat(notify): Telegram/email/webhook + dedup/throttle
(#8)  feat(infra): automatic migration runner + CI + gateway/worker in compose
(#7)  feat(respond): response engine + block + approval + progressive ban
(#6)  feat(enrich): real AbuseIPDB/OTX clients + GeoIP + shown in UI
(#5)  feat(agent): FIM + native Windows Service + Agents UI page
(#4)  feat(detect): Sigma->SQL aggregation path + new rules
... (Phase 1: auth/agent/enrich/UI/pipeline/foundation) - see `git log`
```
