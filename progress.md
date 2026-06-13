# DeusWatch — Progress & Handoff

> Catatan progres untuk lanjut di mesin lain. Sumber kebenaran desain: [DeusWatch.md](DeusWatch.md).
> Terakhir diperbarui: 2026-06-13.

## Ringkasan status

Platform deteksi keamanan **jalan end-to-end**. 22 commit di `main`
(github.com/FirdausYudha/DeusWatch). Stack: Go (agent/gateway/worker/api),
PostgreSQL+TimescaleDB, NATS JetStream, React+Vite+Tailwind.

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
| Deteksi | brute-force SSH (agregasi) + **Sigma engine** (field/keyword/alias/MITRE), `rules/sigma/` | ✅ (interim evaluator; lihat ADR) |
| Enrichment CTI | `internal/enrich` + cache TTL Postgres (`cti_indicators`) + eskalasi severity; provider mock | ✅ (klien AbuseIPDB/OTX nyata = TODO) |
| Auth | login, sesi, **RBAC** (viewer/analyst/admin), **audit log append-only**, manajemen user, **TOTP 2FA** | ✅ + UI |
| Web UI | Login, Dashboard (stats/alert/health live), Users (admin), Settings (2FA) | ✅ |
| **Agent (fokus terakhir)** | **enrollment per-agent** (token sekali-pakai→cert unik+revoke), **config push** terpusat, **heartbeat + buffer offline** (store-and-forward), kolektor per-OS (build tag: Linux file/journald, Windows Event Log), cross-compile | ✅ |

Total ~26 test (unit + integrasi + e2e) lulus. Keputusan Sigma: [docs/adr/0001-sigma-detection-engine.md](docs/adr/0001-sigma-detection-engine.md).

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
- Engine Sigma saat ini = prototipe internal (interim) di balik antarmuka `detect.Detector`.

## Belum dikerjakan (roadmap berikutnya)

- **Sigma**: jalur pySigma→SQL untuk rule agregasi + dry-run histori; evaluasi adopsi fork Go matang; lebih banyak rule + perluas dataset (process/file/web).
- **Enrichment**: klien AbuseIPDB/OTX + GeoIP nyata; aturan eskalasi configurable dari UI; tampilkan enrichment di UI alert.
- **Agent**: FIM (file integrity), native Windows Service (kini Scheduled Task), canary deploy config, drift indicator di UI; halaman Agents di UI (saat ini hanya API).
- **Response engine** (Fase 2): nftables/Mikrotik/CrowdSec LAPI + dry-run + ban progresif.
- **Notifikasi** (Fase 2): Telegram/email/webhook + dedup/throttle.
- **Infra**: runner migrasi otomatis, CI (govulncheck/gosec/test), pin versi image, jalankan gateway/worker di compose.
- **LLM worker** (Fase 3), report, community blocklist.

## Peta commit (terbaru → lama, sebagian)

```
88394ce heartbeat + buffer offline (#3)
07f2771 config push terpusat (#2)
d77aa3b enrollment per-agent (#1)
3b12943 kolektor multi-source per-OS + cross-compile + installer
1066763 CTI enrichment + cache TTL + eskalasi severity
53fb6f2 UI 2FA (Settings)
7ce72db TOTP 2FA
ac1cb69 manajemen user + RBAC enforcement
96ec0ab login + sesi + middleware + UI login
25fa519 fondasi auth (Argon2id, RBAC, migrasi)
6b35f83 spike Sigma + ADR
... (init s/d API/UI/pipeline) — lihat `git log`
```
