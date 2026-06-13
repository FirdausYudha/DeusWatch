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

# 1. Nyalakan infra (db + nats + api)
docker compose -f deploy/docker-compose.yml up -d --build

# 2. Terapkan SEMUA migrasi (BELUM ada runner otomatis — jalankan manual, urut)
for f in migrations/0000{1,2,3,4,5}_*.up.sql; do
  docker compose -f deploy/docker-compose.yml exec -T db \
    psql -U deuswatch -d deuswatch -v ON_ERROR_STOP=1 < "$f"
done
# (PowerShell: Get-Content -Raw <file> | docker compose ... exec -T db psql ... )

# 3. Generate sertifikat mTLS (dibutuhkan gateway/agent + enrollment di api)
go run ./cmd/certgen --out deploy/certs
docker compose -f deploy/docker-compose.yml restart api   # agar api memuat CA

# 4. Web UI
cd web && npm install && npm run dev      # http://localhost:5173
```

**Login dev:** `admin` / `deuswatch-admin` (di-seed otomatis; ganti via env `ADMIN_PASSWORD`).

## Menjalankan pipeline penuh (gateway + worker + agent lokal)

gateway/worker/agent **belum** di docker-compose — jalankan sebagai biner lokal.
Set env lalu jalankan (contoh PowerShell di `bin/`):

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

- **Migrasi manual** — belum ada runner (golang-migrate belum diwire). DB fresh wajib jalankan 5 migrasi.
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
