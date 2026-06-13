<div align="center">

# DeusWatch

**Platform Keamanan All-in-One, Open Source, Self-Hosted.**

SIEM · IDS/IPS · SOAR ringan · CTI enrichment · analisis berbasis LLM — dalam satu sistem ringan & modular.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Fase%201%20(WIP)-orange.svg)]()

</div>

---

> ⚠️ **Status: pengembangan awal (Fase 1).** Belum siap produksi. Fondasi sedang dibangun.

## Apa itu DeusWatch?

DeusWatch menggabungkan deteksi dan respons keamanan dalam satu paket yang bisa dijalankan
dengan satu perintah `docker compose up`. Dirancang ramah pemula secara default, namun
sepenuhnya dapat dikustomisasi untuk profesional SOC.

Prinsip utama: **jangan reinvent the wheel.** Kami memanfaatkan standar matang
(Sigma rules, protokol bouncer CrowdSec, PostgreSQL, NATS) dan fokus membangun lapisan
integrasi serta pengalaman pengguna yang belum dimiliki vendor manapun dalam satu paket.

## Fitur (peta jalan)

| Fase | Cakupan |
|---|---|
| **Fase 1** (sekarang) | Agent Linux, ingest mTLS, gateway + normalisasi, NATS, Postgres+TimescaleDB, Sigma detection (SSH brute force dll.) + auto-label MITRE, API + RBAC + audit log, Web UI dasar |
| Fase 2 | Agent Windows/macOS, CTI enrichment (AbuseIPDB/OTX), response engine (nftables/Mikrotik/CrowdSec LAPI), TOTP 2FA |
| Fase 3 | LLM worker (RAG via pgvector), report otomatis, community blocklist, ML anomaly baseline |
| Fase 4 | Agent Android, marketplace rule/integrasi, Helm chart |

## Arsitektur singkat

```
Agent (Go) ──mTLS──> Ingest Gateway ──> NATS JetStream ──> Worker (detect/enrich/respond/llm)
                                                                  │
                                          PostgreSQL 16 + TimescaleDB + pgvector
                                                                  │
                                              API Server (Go) ──> Web UI (React + Vite)
```

Detail desain lengkap: lihat [DeusWatch.md](DeusWatch.md).

## Quick start

> Belum tersedia — akan diisi saat skeleton `docker-compose` siap (langkah 2 fondasi).

```bash
# (segera hadir)
git clone <repo>
cd deuswatch
docker compose -f deploy/docker-compose.yml up
```

## Teknologi

Go · PostgreSQL + TimescaleDB · pgvector · NATS JetStream · Sigma · React + Vite + Tailwind ·
Docker · LLM provider-agnostic (Ollama / OpenAI-compatible / Anthropic).

## Keamanan

Sistem keamanan yang tidak aman adalah ironi. mTLS wajib, RBAC sejak hari pertama,
secrets terenkripsi, audit log append-only. Lihat [SECURITY.md](SECURITY.md) untuk
kebijakan responsible disclosure.

## Lisensi

[AGPL-3.0](LICENSE) — bebas self-host selamanya, anti vendor lock-in.

## Dukungan

♥ Suka DeusWatch? Pertimbangkan mendukung lewat tombol **Sponsor** di repo ini
(Saweria untuk Indonesia, Ko-fi untuk internasional).
