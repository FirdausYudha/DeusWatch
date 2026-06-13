# DeusWatch — Progress & Handoff

> Catatan progres untuk lanjut di mesin lain. Sumber kebenaran desain: [DeusWatch.md](DeusWatch.md).
> Terakhir diperbarui: 2026-06-14.

## Ringkasan status

Platform deteksi keamanan **jalan end-to-end**, Fase 1–3 selesai. Stack: Go
(agent/gateway/worker/api), PostgreSQL+TimescaleDB, NATS JetStream, React+Vite+Tailwind.
Diverifikasi live: pipeline event→deteksi(Sigma single+agregasi)→enrich→alert→
respons(dry-run)→LLM triase→report.

```
agent ──mTLS──▶ gateway ──▶ NATS ──▶ worker(enrich+detect) ──▶ TimescaleDB ──▶ API ──▶ Web UI
```

## Sudah selesai & terverifikasi

| Area | Isi | Status |
|---|---|---|
| Fondasi | monorepo, docker-compose (db/nats/api), mTLS lintas-OS (CA+cert) | ✅ |
| Schema DCS | `internal/ingest/schema.go` + hypertable TimescaleDB (chunk/hari, kompresi, retensi) | ✅ |
| Pipeline | `internal/bus` (NATS), `internal/store` (pgx), `internal/worker` | ✅ |
| Ingest | gateway mTLS + normalisasi sshd → DCS; agent tail → kirim | ✅ |
| Deteksi | Sigma single-event (field/keyword/alias/MITRE) + **jalur agregasi Sigma→SQL** (compile ke query TimescaleDB, runner periodik+cooldown+dry-run), `rules/sigma/` (+`agg/`) | ✅ |
| Enrichment CTI | `internal/enrich` + cache TTL Postgres + **klien nyata AbuseIPDB/OTX + GeoIP** (ip-api) + eskalasi configurable + **community blocklist** | ✅ + tampil di UI |
| **Response engine** (Fase 2) | `internal/respond`: nftables/CrowdSec/Mikrotik + dry-run + **ban progresif** + approval workflow (API) | ✅ |
| **Notifikasi** (Fase 2) | `internal/notify`: Telegram/email/webhook + dedup/throttle | ✅ |
| **LLM worker** (Fase 3) | `internal/llm`: triase alert→vonis (Claude SDK / heuristik) → `deuswatch.llm.*` | ✅ + UI |
| **Report** (Fase 3) | `internal/report` + `GET /api/report` (JSON/Markdown) | ✅ |
| Auth | login, sesi, **RBAC**, **audit log append-only**, manajemen user, **TOTP 2FA** | ✅ + UI |
| Web UI | Login, Dashboard (stats/alert/threat-intel/LLM live), **Agents**, Users, Settings | ✅ |
| Agent | enrollment per-agent, config push, heartbeat+buffer offline, **FIM**, **Windows Service native**, kolektor per-OS, cross-compile | ✅ |
| Infra | **runner migrasi otomatis** (embed), **CI** (vet/test/govulncheck/gosec/web), image di-pin, gateway+worker di compose | ✅ |

Semua test (unit + integrasi + e2e) lulus; gosec & govulncheck bersih. ADR Sigma: [docs/adr/0001-sigma-detection-engine.md](docs/adr/0001-sigma-detection-engine.md).

## Prasyarat di PC baru

- **Go 1.25+** (dikembangkan dgn 1.26)
- **Docker Desktop**
- **Node 22+** (untuk web)

## Setup di PC baru (urutan)

```bash
git clone https://github.com/FirdausYudha/DeusWatch.git
cd DeusWatch

# 1. Nyalakan stack penuh (db + nats + api + gateway + worker)
docker compose -f deploy/docker-compose.yml up -d --build

# 2. Migrasi OTOMATIS saat api start (runner in-house, idempotent).
#    Manual bila perlu: DATABASE_URL=... go run ./cmd/migrate
#    Nonaktifkan auto: RUN_MIGRATIONS=0

# 3. Generate sertifikat mTLS (dibutuhkan gateway/agent + enrollment di api)
go run ./cmd/certgen --out deploy/certs
docker compose -f deploy/docker-compose.yml restart api gateway   # agar memuat CA/cert

# 4. Web UI
cd web && npm install && npm run dev      # http://localhost:5173
```

**Login dev:** `admin` / `deuswatch-admin` (di-seed otomatis; ganti via env `ADMIN_PASSWORD`).

## Menjalankan pipeline penuh (agent lokal)

gateway/worker kini **sudah di docker-compose** (langkah 1 menyalakannya). Hanya
**agent** yang dijalankan di endpoint terpisah. Untuk menjalankan biner secara lokal
(dev), set env lalu jalankan (contoh PowerShell di `bin/`):

```
NATS_URL=nats://localhost:4222
STORE_DSN=postgres://deuswatch:deuswatch_dev@localhost:5432/deuswatch?sslmode=disable
CERT_DIR=deploy/certs            # gateway/worker pakai server cert + CA
RULES_DIR=rules/sigma
GATEWAY_ADDR=:8443

go build -o bin/gateway.exe ./cmd/gateway   # + worker, agent
# jalankan gateway, worker, lalu agent (agent: GATEWAY_URL=https://localhost:8443)
```

Cross-compile agent semua OS: `./scripts/build-agent.sh` → `dist/`.
Install agent: `deploy/agent/` (systemd `install-linux.sh`, Windows `install-windows.ps1`).

### Alur enrollment agent (gaya Wazuh)
1. Admin buat token: `POST /api/agents/tokens` (Bearer admin) → `{token}`.
2. Agent tukar token: `agent -enroll -token <T> -name <nama> -manager http://host:8080 -out <certdir>`.
3. Agent jalan normal pakai cert itu; muncul di `GET /api/agents`; bisa di-revoke.
4. Config push: admin `PUT /api/agents/{id}/config {sources:[...]}`; agent ambil via gateway saat start + poll (versi naik → restart terapkan).

## Catatan/gotcha penting

- **Migrasi otomatis** — runner in-house (`internal/migrate` + embed di package `migrations`); api menerapkannya saat start (idempotent). Standalone: `cmd/migrate`. `RUN_MIGRATIONS=0` untuk nonaktif.
- **Image di-pin**: timescaledb `2.17.2-pg16`, nats `2.10.22-alpine`. Mengubah pin pada volume lama yang dibuat versi lain bisa bentrok — pakai volume fresh.
- **CI**: `.github/workflows/ci.yml` (vet/build/test dgn services pg+nats, govulncheck, gosec, web tsc+build). gosec mengecualikan rule yang melekat domain (lihat workflow).
- **Response engine**: `RESPONDER=dryrun|nftables|crowdsec|mikrotik|none` (default dryrun). nftables/crowdsec/mikrotik DIBUNGKUS dry-run kecuali `RESPONSE_LIVE=1`. `RESPONSE_AUTO_APPROVE=1` eksekusi tanpa approval. Approve/dismiss via `POST /api/responses/{id}/approve|dismiss`.
- **Notifikasi**: aktif bila salah satu saluran diisi — `TELEGRAM_BOT_TOKEN`+`TELEGRAM_CHAT_ID`, `WEBHOOK_URL`, atau `SMTP_HOST`+`SMTP_FROM`+`SMTP_TO`(+`SMTP_USER`/`SMTP_PASS`). Ambang `NOTIFY_MIN_SEVERITY` (default high), dedup `NOTIFY_THROTTLE` (default 10m, per rule+IP). Worker memanggilnya via `worker.AlertHook` (bersama response engine).
- **Worker LLM** (Fase 3): `ANTHROPIC_API_KEY` → analyzer Claude (model `ANTHROPIC_MODEL`, default `claude-opus-4-8`, via SDK resmi); `LLM_ENABLED=1` → analyzer heuristik offline. Worker mem-poll alert tanpa vonis tiap 20s → isi `deuswatch.llm.*`.
- **Report**: `GET /api/report?hours=24` (JSON) atau `?format=md` (Markdown) — ringkasan event/alert/severity/top IP/rule/MITRE/vonis.
- **Community blocklist**: `BLOCKLIST_URLS` (feed IP/CIDR dipisah koma) → IP yang cocok ditandai abuse=100 (feed `blocklist`); refresh tiap `BLOCKLIST_REFRESH` (default 6h).
- **Enrichment CTI nyata**: set `ABUSEIPDB_API_KEY` / `OTX_API_KEY` / `GEOIP_ENABLED=1` di env worker (tanpa itu pakai provider mock). Ambang eskalasi: `ABUSE_ESCALATE_THRESHOLD` (default 90), `OTX_ESCALATE_THRESHOLD` (default 5).
- **bin/ & dist/ & deploy/certs/ di-gitignore** — rebuild biner & regen cert di PC baru.
- Saat ubah kode service, **rebuild biner** sebelum demo (beberapa bug demo karena biner stale).
- `gateway` butuh `STORE_DSN` untuk revocation/config-push/heartbeat (opsional; tanpa DB fitur itu nonaktif).
- Detektor `detect-worker`… durable NATS pakai DeliverNew (tak replay backlog).
- Engine Sigma single-event = evaluator interim; jalur agregasi = compiler in-Go ke SQL (ADR 0001 addendum).
- Mengubah pin image TimescaleDB pada volume lama yang dibuat versi lain → bentrok (`$libdir`); pakai volume fresh.

## Roadmap utama (Fase 1–3) — SELESAI ✅

Tujuh item roadmap berikut sudah diimplementasikan, diuji, dan diverifikasi end-to-end:
Sigma agregasi→SQL+rule baru (#4); FIM+Windows Service native+halaman Agents (#5);
klien CTI nyata+GeoIP+UI (#6); response engine+ban progresif (#7); infra migrasi/CI/
compose (#8); notifikasi (#9); LLM worker+report+blocklist (#10).

## Ide lanjutan (opsional)

- Sigma: adopsi fork Go matang untuk single-event; perluas dataset (process/web); aturan eskalasi & ban dari UI.
- UI: halaman Response/Actions (approve/dismiss dari UI), halaman Report, drift indicator agent.
- Agent: canary deploy config, FIM real-time (fsnotify) sebagai ganti polling.
- pgvector untuk RAG/LLM (kolom embedding disiapkan di schema).

## Peta commit (terbaru → lama, sebagian)

```
(#10) feat(llm): worker LLM + report + community blocklist (Fase 3)
(#9)  feat(notify): Telegram/email/webhook + dedup/throttle
(#8)  feat(infra): runner migrasi otomatis + CI + gateway/worker di compose
(#7)  feat(respond): response engine + blokir + approval + ban progresif
(#6)  feat(enrich): klien AbuseIPDB/OTX + GeoIP nyata + tampil di UI
(#5)  feat(agent): FIM + Windows Service native + halaman Agents UI
(#4)  feat(detect): jalur agregasi Sigma->SQL + rule baru
... (Fase 1: auth/agent/enrich/UI/pipeline/fondasi) — lihat `git log`
```
