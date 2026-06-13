# DeusWatch — Design Document
## Platform Keamanan All-in-One Open Source

> Dokumen ini adalah blueprint untuk dibawa ke Claude Code. Versi 1.0 — semua keputusan desain final.
> Nama resmi: **DeusWatch**. Schema: **DCS (DeusWatch Core Schema)**. Lisensi: **AGPL-3.0**.

---

## 1. Visi

Platform deteksi dan respons keamanan open-source yang menggabungkan kemampuan SIEM, IDS/IPS, SOAR ringan, CTI enrichment, dan analisis berbasis LLM dalam satu sistem yang ringan, modular, dan sepenuhnya self-hosted. Target pengguna mencakup pemula (noob-friendly default) hingga profesional SOC (fully customizable), dengan semua komponen berjalan di Docker dan mudah dimigrasi.

Prinsip utama: **jangan reinvent the wheel**. Kita memanfaatkan standar dan ekosistem yang sudah matang (Sigma rules, protokol bouncer CrowdSec, PostgreSQL, NATS) dan fokus membangun lapisan integrasi serta pengalaman pengguna yang belum dimiliki vendor manapun dalam satu paket.

---

## 2. Arsitektur Tingkat Tinggi

```
┌─────────────────────────────────────────────────────────────────┐
│                          ENDPOINTS                              │
│   Agent (Go, single binary) — Linux / Windows / macOS          │
│   Mengirim: raw logs, FIM events, system metrics                │
└──────────────────────────┬──────────────────────────────────────┘
                           │ mTLS (wajib, tanpa opsi plaintext)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    INGEST GATEWAY (Go)                          │
│   Autentikasi agent, rate limiting, validasi schema,            │
│   normalisasi log ke format internal (mirip ECS)                │
└──────────────────────────┬──────────────────────────────────────┘
                           │ publish
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              NATS JetStream (message bus + persistence)         │
│   Stream: logs.raw → logs.normalized → logs.enriched → alerts  │
│   Tidak ada cache, tidak ada tabrakan cache. Pure streaming.    │
└───────┬──────────────┬───────────────┬──────────────┬───────────┘
        ▼              ▼               ▼              ▼
┌──────────────┐ ┌─────────────┐ ┌────────────┐ ┌──────────────┐
│  DETECTION   │ │ ENRICHMENT  │ │  RESPONSE  │ │  LLM WORKER  │
│  ENGINE      │ │ WORKER      │ │  ENGINE    │ │              │
│  Sigma rules │ │ CTI lookup: │ │ Bouncer:   │ │ Mode:        │
│  + auto-     │ │ AbuseIPDB,  │ │ Mikrotik,  │ │ per-log /    │
│  labelling   │ │ OTX, GeoIP  │ │ nftables,  │ │ per-enriched │
│  (MITRE tag) │ │ + cache TTL │ │ CrowdSec   │ │ / batch      │
│              │ │ di Postgres │ │ LAPI compat│ │ harian       │
└──────┬───────┘ └──────┬──────┘ └─────┬──────┘ └──────┬───────┘
       └────────────────┴──────────────┴───────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│   PostgreSQL 16 + TimescaleDB (log time-series, kompresi,       │
│   retention policy) + pgvector (embedding untuk RAG/LLM)        │
│   Replication: streaming replication / Patroni untuk HA         │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│   API SERVER (Go) ── REST + WebSocket, RBAC, audit log          │
│   WEB UI (React + Vite) ── dashboard customizable (grid         │
│   drag-and-drop), dark mode, modern, real-time via WebSocket    │
└─────────────────────────────────────────────────────────────────┘
```

Setiap kotak adalah satu container Docker. Semua diorkestrasi lewat satu `docker-compose.yml` (mode noob-friendly) dengan opsi Helm chart untuk Kubernetes di masa depan (mode pro).

---

## 3. Keputusan Teknologi dan Alasannya

| Komponen | Pilihan | Alasan |
|---|---|---|
| Bahasa inti & agent | Go | Single binary, ringan, cross-compile Linux/Windows/macOS, concurrency bagus untuk ingest |
| Message bus | NATS JetStream | Persistence built-in, jauh lebih ringan dari Kafka, bukan cache sehingga tidak ada masalah tabrakan cache seperti di Shuffle |
| Database log | PostgreSQL + TimescaleDB | Time-series native, kompresi kolom, retention otomatis, replication matang |
| Vector / RAG | pgvector (extension Postgres) | LLM bisa semantic search ke log historis tanpa database tambahan |
| Rule deteksi | Sigma | Ribuan rule community, tag MITRE ATT&CK gratis = auto-labelling (brute force, password guessing, dst.) |
| Bouncer/IPS | Implementasi protokol CrowdSec LAPI | Kompatibel dengan semua bouncer CrowdSec yang sudah ada + bisa subscribe blocklist community CrowdSec |
| Frontend | React + Vite + Tailwind | Modern, cepat, ekosistem komponen luas |
| LLM | Provider-agnostic | Ollama (lokal/privasi), OpenAI-compatible API, Anthropic API — user pilih sendiri |

Keputusan penting tentang **enrichment cache** (pelajaran dari Shuffle): hasil lookup CTI disimpan sebagai **baris di Postgres dengan kolom TTL**, bukan di cache in-memory. Worker mengecek tabel dulu sebelum memanggil API eksternal. Deterministic, bisa di-query, tidak pernah "tabrakan" — kalau dua worker lookup IP yang sama bersamaan, constraint unik di database yang menyelesaikannya, bukan logika cache.

---

## 4. Security-by-Design (Non-Negotiable)

Sistem keamanan yang tidak aman adalah ironi. Aturan berikut berlaku sejak commit pertama dan tidak boleh dilanggar demi kemudahan development.

**Komunikasi agent–server.** Seluruh komunikasi agent menggunakan mTLS. Tidak ada mode plaintext, bahkan untuk development (gunakan sertifikat self-signed yang di-generate otomatis oleh installer). Enrollment agent memakai token sekali-pakai dengan masa berlaku pendek; setelah enroll, agent mendapat sertifikat client unik yang bisa dicabut individual dari UI.

**Autentikasi dan otorisasi.** RBAC sejak hari pertama dengan tiga role bawaan: **Viewer** (hanya melihat dashboard dan alert — read-only murni, cocok untuk manajemen/monitoring screen), **Analyst** (membaca semuanya, investigasi, acknowledge alert, dan meng-approve rekomendasi remediasi — tetapi tidak bisa mengedit rule, settings, atau user; ini role "discovery" yang bisa menggali tanpa bisa merusak), dan **Admin** (full read-write-execute: kelola rule, user, integrasi, retensi, dan eksekusi blocking). Mode pro menambahkan **custom role builder**: admin bisa merakit role sendiri dari permission granular (misal role khusus yang boleh kelola rule tapi tidak boleh kelola user). Password di-hash dengan Argon2id. Dukungan TOTP 2FA di MVP, bukan "nanti". Session memakai token dengan rotasi, bukan JWT berumur panjang. Semua aksi yang mengubah state (block IP, ubah rule, hapus data) tercatat di audit log yang append-only beserta identitas role pelakunya.

**Secrets.** API key CTI, kredensial Mikrotik, dan API key LLM disimpan terenkripsi di database dengan envelope encryption (master key dari environment variable atau file, dengan dokumentasi integrasi Vault untuk mode pro). Secrets tidak pernah muncul di log aplikasi dan di-mask di UI.

**Supply chain.** Binary agent dan image Docker ditandatangani (cosign). CI menjalankan `govulncheck`, `gosec`, dan dependency scanning di setiap PR. SBOM di-generate untuk setiap release. Karena ini open source di GitHub, sertakan SECURITY.md dengan kebijakan responsible disclosure.

**Input handling.** Semua log yang masuk diperlakukan sebagai data berbahaya: validasi schema di gateway, parameterized query tanpa pengecualian, sanitasi sebelum render di UI (log injection ke dashboard adalah vektor serangan nyata terhadap analis SOC). Khusus fitur LLM: log yang dikirim ke LLM bisa mengandung prompt injection dari penyerang — output LLM **tidak pernah** dieksekusi otomatis sebagai aksi blocking; LLM hanya memberi rekomendasi yang harus dikonfirmasi manusia, kecuali user secara eksplisit mengaktifkan auto-mode dengan level kepercayaan yang bisa diatur.

**Autoblocking yang aman.** Response engine punya safeguard wajib: allowlist (IP admin tidak pernah diblok), dry-run mode default saat instalasi pertama, TTL pada setiap block (tidak ada block permanen tanpa konfirmasi), dan rollback satu-klik. Level agresivitas bisa diatur per-sumber-deteksi (poin 19 dari requirement).

---

## 5. Struktur Repo (Monorepo)

```
deuswatch/
├── cmd/
│   ├── agent/            # entrypoint agent (single binary)
│   ├── gateway/          # ingest gateway
│   ├── api/              # API server
│   └── worker/           # detection, enrichment, response, llm
│                         # (satu binary, mode dipilih via flag)
├── internal/
│   ├── agent/            # kolektor log per-OS, FIM (fsnotify + hashing)
│   ├── ingest/           # normalisasi, schema internal (mirip ECS)
│   ├── detect/           # Sigma engine, auto-labelling MITRE
│   ├── enrich/           # klien AbuseIPDB, OTX, GeoIP + TTL store
│   ├── respond/          # driver Mikrotik API, nftables, CrowdSec LAPI
│   ├── llm/              # provider abstraction, RAG via pgvector
│   ├── store/            # Postgres/Timescale, migrasi, repository
│   ├── auth/             # RBAC, Argon2id, TOTP, audit log
│   └── bus/              # abstraksi NATS JetStream
├── web/                  # React + Vite + Tailwind
│   ├── src/
│   │   ├── dashboard/    # grid customizable (drag-drop widget)
│   │   ├── alerts/
│   │   ├── agents/
│   │   ├── rules/        # editor Sigma + blocklist manager
│   │   └── settings/
├── deploy/
│   ├── docker-compose.yml          # mode noob: satu perintah jalan
│   ├── docker-compose.prod.yml    # mode pro: replication, resource limit
│   └── certs/                      # script generate mTLS otomatis
├── .github/
│   └── FUNDING.yml       # Saweria + Ko-fi → tombol Sponsor otomatis
├── rules/                # bundle Sigma rules default + rule custom
├── migrations/           # SQL migration (golang-migrate)
├── docs/
├── SECURITY.md
├── LICENSE               # AGPL-3.0 (DIPUTUSKAN) — anti vendor-lock,
│                         #  membuka jalur monetisasi hosted version
└── README.md
```

---

## 6. Spec MVP Fase 1 (target: bisa dipakai orang lain)

Ruang lingkup Fase 1 sengaja kecil agar selesai. Definisi selesai: seseorang bisa `docker compose up`, install agent dengan satu perintah curl, dan dalam lima menit melihat log servernya masuk ke dashboard dengan alert brute force SSH yang terdeteksi otomatis.

**Termasuk di Fase 1:** agent Linux (log file + journald + FIM dasar), enrollment mTLS, gateway + normalisasi, NATS JetStream, Postgres + TimescaleDB, detection engine dengan subset Sigma rules (fokus: SSH brute force, web attack umum, auth anomali) plus auto-labelling dari tag MITRE, API server dengan RBAC + audit log, dan Web UI dengan live log stream, halaman alert, manajemen agent, serta dashboard grid sederhana (3–4 tipe widget: time-series, counter, top-N table, pie).

**Eksplisit TIDAK termasuk Fase 1:** agent Windows/macOS (Fase 2), CTI enrichment (Fase 2 — tapi schema database sudah menyiapkan kolomnya), autoblocking (Fase 2), LLM (Fase 3), ML anomaly detection (Fase 3), community blocklist sharing (Fase 3), report generator (Fase 3).

**Roadmap ringkas.** Fase 2: agent Windows + macOS, enrichment AbuseIPDB/OTX dengan TTL store, response engine (Mikrotik + nftables + CrowdSec LAPI compat) dengan dry-run dan level agresivitas, TOTP 2FA. Fase 3: LLM worker (tiga mode trigger), RAG via pgvector, report harian/bulanan/tahunan powered by LLM, community blocklist publish/subscribe, ML anomaly baseline. Fase 4: Android agent, marketplace rule/integrasi, Helm chart.

---

## 7. DCS — DeusWatch Core Schema (DIPUTUSKAN)

Keputusan: **subset dengan penamaan ECS**. Semua field inti mengikuti nama dan struktur resmi Elastic Common Schema agar Sigma rules community langsung kompatibel; field yang tidak ada padanannya di ECS masuk ke namespace custom `deuswatch.*`. Schema ini dirancang untuk tiga konsumen utama: agregasi dashboard, enrichment CTI, dan konteks untuk LLM.

**Grup field inti (ECS-compliant):**

| Grup | Field utama | Untuk apa |
|---|---|---|
| Event | `@timestamp`, `event.category`, `event.action`, `event.outcome`, `event.severity`, `event.dataset`, `event.original` | Dasar semua agregasi dashboard (time-series, severity breakdown) |
| Source/Dest | `source.ip`, `source.port`, `source.geo.country_iso_code`, `source.geo.city_name`, `destination.ip`, `destination.port` | Top-N IP penyerang, peta geografis, kunci utama enrichment |
| Host & Agent | `host.name`, `host.os.type`, `host.ip`, `agent.id`, `agent.version` | Filter per-endpoint, manajemen agent |
| User | `user.name`, `user.domain` | Deteksi brute force per-akun, password guessing |
| Network | `network.protocol`, `network.transport` | Breakdown protokol |
| File (FIM) | `file.path`, `file.hash.sha256`, `file.owner`, `file.mode` | File Integrity Monitoring |
| Process | `process.name`, `process.pid`, `process.command_line` | Konteks endpoint (Fase 2+) |
| Deteksi | `rule.id`, `rule.name`, `threat.technique.id`, `threat.technique.name`, `threat.tactic.name` | Auto-labelling MITRE ATT&CK dari tag Sigma |
| Enrichment CTI | `threat.indicator.ip`, `threat.indicator.confidence`, `threat.feed.name`, `threat.indicator.last_seen` | Hasil lookup AbuseIPDB/OTX — ECS sudah punya fieldset `threat.*` resmi untuk ini |

**Namespace custom `deuswatch.*`** (untuk yang ECS tidak punya):

| Field | Isi |
|---|---|
| `deuswatch.enrichment.status` | `pending` / `enriched` / `failed` / `skipped` — status pipeline per-log |
| `deuswatch.enrichment.abuse_confidence` | Skor 0–100 dari AbuseIPDB (dipakai dashboard dan threshold autoblocking) |
| `deuswatch.enrichment.otx_pulse_count` | Jumlah pulse OTX yang memuat IP tersebut |
| `deuswatch.label` | Label hasil auto-labelling: `bruteforce`, `password_guessing`, `mailscam`, dst. |
| `deuswatch.llm.verdict` | `benign` / `suspicious` / `malicious` / `needs_review` |
| `deuswatch.llm.summary` | Ringkasan analisis LLM (juga di-embed ke pgvector untuk RAG) |
| `deuswatch.llm.analyzed_at` | Timestamp analisis, untuk mode batch harian |

Desain alur datanya: log masuk dengan `deuswatch.enrichment.status = pending` → enrichment worker mengisi fieldset `threat.*` + skor → LLM worker membaca log **yang sudah enriched** (sesuai mode trigger) dan mengisi `deuswatch.llm.*`. Dashboard tinggal agregasi field-field ini tanpa parsing tambahan — semuanya kolom terindeks di TimescaleDB.

Aturan disiplin schema: field baru hanya boleh ditambah lewat PR yang mengubah file definisi schema tunggal (`internal/ingest/schema.go` + migrasi SQL), tidak boleh ada field liar yang muncul dadakan di kode. Ini mencegah schema membusuk seiring waktu.

---

## 8. Penyimpanan & Retensi Log

Tabel log adalah **hypertable TimescaleDB dengan chunk per-hari** — setiap hari adalah partisi fisik terpisah, sehingga penghapusan data lama berupa drop chunk yang instan dan tidak membebani database. Tiga mekanisme retensi berjalan di atasnya, semuanya dapat dikonfigurasi dari UI:

**Retention policy berbasis waktu, per kategori data.** Setiap kategori punya umur sendiri yang bisa diatur bebas (7 hari / 30 hari / 90 hari / 1 tahun / selamanya). Default yang masuk akal: raw logs 30 hari (volume terbesar, nilai forensik cepat basi), alert + log enriched 1 tahun, audit log 2 tahun. Implementasi: `add_retention_policy()` bawaan TimescaleDB.

**Kompresi otomatis.** Chunk lebih tua dari 7 hari (configurable) dikompres dengan columnar compression TimescaleDB — penghematan tipikal 90%+, dan data terkompres tetap bisa di-query. Inilah yang membuat retensi 1 tahun realistis di disk kecil: estimasi kasar, log mentah 500 GB/tahun menyusut ke ±50–70 GB.

**Janitor berbasis disk watermark (safety net).** Service ringan memantau penggunaan disk volume data. Saat melewati watermark (default **90%**, configurable — sengaja bukan 98% karena PostgreSQL yang kehabisan disk berisiko korupsi dan berhenti total), janitor menghapus chunk tertua lebih dini dari jadwal retensinya sampai penggunaan turun ke level aman. Setiap pemicu janitor menghasilkan alert severity `high` agar admin tahu disk perlu diperbesar atau retensi perlu diperketat.

**Arsip dingin (opsional, Fase 3).** Sebelum chunk dihapus oleh retensi atau janitor, dapat di-export otomatis ke object storage (MinIO self-hosted / S3) sebagai file Parquet terkompresi — untuk kebutuhan compliance dan forensik jangka panjang tanpa membebani database utama.

Seluruh pengaturan ini tampil di UI Settings → Storage dengan estimasi visual penggunaan disk per kategori, sehingga user noob cukup memakai default sementara user pro bisa mengatur granular.

---

## 9. Severity & Rekomendasi Remediasi Otomatis

**Model severity (5 level):** `info` → `low` → `medium` → `high` → `critical`, disimpan di `event.severity` (numerik 0–4 agar mudah diagregasi dashboard). Sumber severity dasar adalah field `level` bawaan Sigma rule yang nilainya persis sama, jadi tidak perlu mapping rumit. Di atasnya berlaku **eskalasi dinamis** oleh enrichment worker: contoh default, alert apapun dengan `deuswatch.enrichment.abuse_confidence ≥ 90` naik satu level; IP yang muncul di ≥ 5 pulse OTX naik satu level; semua aturan eskalasi bisa dikustomisasi dari UI. Severity hasil eskalasi disimpan terpisah dari severity asli agar tetap auditable.

**Rekomendasi remediasi: arsitektur hybrid dua lapis.**

Lapis pertama, **rule-based (utama)**: setiap label deteksi dipetakan ke playbook rekomendasi statis di file YAML (`rules/playbooks/`). Contoh: label `bruteforce` → rekomendasi "block source.ip dengan TTL 24 jam, audit akun target, verifikasi rate-limiting SSH". Deterministic, <1ms, tanpa biaya, sepenuhnya auditable, dan menangani mayoritas volume log. Playbook bisa ditambah/diedit user dari UI (fully customizable).

Lapis kedua, **LLM (penasihat)**: dipicu hanya untuk kasus yang rule-based angkat tangan — severity `high`/`critical` tanpa playbook yang cocok, pola anomali baru, atau korelasi multi-log. LLM menerima log enriched + konteks historis dari pgvector (RAG) dan menghasilkan rekomendasi naratif. Sesuai prinsip keamanan bagian 4: rekomendasi LLM **tidak pernah dieksekusi otomatis** — selalu butuh konfirmasi manusia, karena konten log dari penyerang adalah vektor prompt injection.

Field tambahan di namespace `deuswatch.*`:

| Field | Isi |
|---|---|
| `deuswatch.severity.original` | Severity asli dari Sigma rule |
| `deuswatch.severity.escalated_by` | Aturan eskalasi yang menaikkan level (audit trail) |
| `deuswatch.remediation.action` | Rekomendasi aksi (dari playbook atau LLM) |
| `deuswatch.remediation.source` | `playbook` / `llm` |
| `deuswatch.remediation.status` | `recommended` / `approved` / `executed` / `dismissed` |

Hubungan dengan response engine (autoblocking): playbook bisa menandai aksi tertentu sebagai *auto-executable* (misal block IP untuk `bruteforce` dengan confidence tinggi) sesuai level agresivitas yang diatur user — sedangkan rekomendasi bersumber LLM selamanya manual-approve.

---

## 10. Response Engine: Banlist Multi-Target, Ban Progresif & Manajemen Rule

**Arsitektur driver (Enforcer).** Semua target blocking diabstraksi lewat satu interface Go: `Enforcer` dengan kontrak `Block(ip, ttl, reason)`, `Unblock(ip)`, `Sync()`. Menambah dukungan perangkat baru = menulis satu driver, tanpa menyentuh logika inti. Roadmap driver:

| Fase | Driver |
|---|---|
| Fase 2 | nftables/iptables (Linux lokal via agent), Windows Firewall (via agent), Mikrotik (RouterOS API) |
| Fase 3 | CrowdSec LAPI (push decision ke ekosistem bouncer CrowdSec), pfSense/OPNsense, generic webhook (untuk perangkat apapun yang punya API) |
| Fase 4 | Cisco (ASA/IOS), Sophos XG, FortiGate |

Satu IP bisa diblok ke banyak target sekaligus (misal: Mikrotik di edge + nftables di server). Tabel `bans` di Postgres adalah *source of truth* — driver hanya eksekutor, dan `Sync()` berkala memastikan state perangkat selalu cocok dengan database (self-healing kalau router di-reboot dan kehilangan rule).

**Ban progresif (recidivism).** Durasi ban naik otomatis untuk pelaku berulang. Default: pelanggaran pertama **5 jam**; jika IP yang sama melakukan aktivitas mencurigakan lagi dalam jendela pengamatan (default 7 hari), durasi dikalikan faktor eskalasi (default 2×): 5 jam → 10 jam → 20 jam → 40 jam, hingga plafon maksimum (default 30 hari). Setelah N kali residivis (default 5), sistem merekomendasikan ban permanen — yang tetap butuh konfirmasi admin. Semua parameter (durasi dasar, faktor, jendela, plafon, ambang permanen) bisa diatur **per-label**: brute force boleh agresif, label lain bisa lebih longgar. Riwayat ban per-IP tersimpan penuh untuk audit dan tampil di halaman detail IP.

**Manajemen rule dua mode (terinspirasi Wazuh, diperbaiki).** Mode **GUI builder** untuk pemula: form visual pilih field DCS → kondisi → threshold → severity, yang di belakang layar menghasilkan Sigma YAML standar. Mode **editor teks** untuk pro: tulis/tempel Sigma YAML langsung dengan validasi syntax real-time. Karena keduanya menghasilkan format yang sama, rule buatan GUI bisa dibuka di editor teks dan sebaliknya. Dua fitur pendukung yang Wazuh tidak punya dengan baik: **dry-run rule** (uji rule baru terhadap log historis di database sebelum diaktifkan — langsung terlihat berapa alert yang akan terpicu, mencegah rule berisik) dan **versioning rule** (setiap perubahan tersimpan seperti riwayat git, rollback satu klik kalau edit baru ternyata merusak).

---

## 11. Notifikasi & Alerting Multi-Channel

Semua channel diabstraksi lewat satu interface `Notifier` (pola yang sama dengan `Enforcer`), sehingga menambah channel baru = satu driver baru. Channel yang didukung:

| Channel | Catatan | Fase |
|---|---|---|
| Email (SMTP) | Universal, untuk alert dan pengiriman report PDF | 2 |
| Telegram | Bot API resmi, gratis, real-time — channel terbaik untuk alert instan | 2 |
| Webhook generik | Sekaligus mencakup Slack, Discord, MS Teams, dan integrasi apapun | 2 |
| ntfy / Gotify | Push notification self-hosted, sejalan dengan filosofi proyek | 3 |
| WhatsApp | **Catatan jujur:** API resmi (WhatsApp Business/Cloud API) berbayar per-pesan dan butuh approval Meta; gateway tidak resmi (mis. berbasis library reverse-engineered) gratis tapi berisiko nomor diblokir. Didukung lewat driver gateway pihak ketiga (Fonnte, dsb.) dengan disclaimer jelas di dokumentasi | 3 |

**Routing cerdas, bukan banjir notifikasi.** Setiap channel punya aturan routing sendiri yang diatur dari UI: ambang severity (misal Telegram hanya `high`/`critical`, email mulai `medium`), filter per-label, dan jam tenang. Dua mekanisme anti spam wajib: **deduplikasi** (alert identik dalam jendela waktu digabung jadi satu pesan "brute force dari 1.2.3.4 — 47 kejadian dalam 10 menit", bukan 47 pesan) dan **throttling** per-channel. Alert fatigue adalah alasan nomor satu analis mengabaikan SIEM — desain ini mencegahnya sejak awal.

**Report lewat channel yang sama.** Report harian/bulanan/tahunan (termasuk yang powered by LLM, bagian roadmap Fase 3) dikirim lewat channel pilihan: ringkasan singkat ke Telegram, PDF lengkap ke email.

---

## 12. Manajemen Agent Terpusat (Zero-Touch)

Prinsip: **tidak pernah ada SSH/RDP ke agent untuk mengubah apapun**. Ini perbaikan langsung atas rasa sakit Wazuh (edit `ossec.conf` per-mesin).

**Pemisahan tanggung jawab yang membuat ini mudah.** Detection rules (Sigma) dievaluasi sepenuhnya di server — agent tidak pernah menyimpan atau mengeksekusi rule. Mengubah rule berlaku seketika untuk semua agent tanpa distribusi apapun. Satu-satunya yang hidup di agent adalah **config pengumpulan**: daftar sumber log (file path, journald unit, Windows Event channel), daftar path FIM beserta opsinya (realtime/scheduled, hash algorithm, exclude pattern), dan parameter operasional (buffer size, batas bandwidth).

**Config push terpusat.** Config agent disimpan di Postgres sebagai *desired state*, dengan tiga lapisan yang saling menimpa: **global** → **group** → **override per-agent**. Agent dikelompokkan via tag bebas (`os:linux`, `role:webserver`, `site:jakarta`) dan satu agent boleh masuk banyak group. Contoh nyata: tambah path FIM `/etc/nginx/` ke group `role:webserver` dari UI → semua web server menerapkannya, mesin lain tidak tersentuh.

**Mekanisme distribusi.** Agent memelihara koneksi mTLS persisten yang sama dengan jalur pengiriman log — config baru dikirim lewat kanal itu (push instan saat online, pull saat reconnect untuk agent yang sempat offline). Setiap config punya nomor versi; agent menerapkannya **atomik** (validasi dulu, terapkan, lapor balik versi yang aktif), dan jika config baru membuat agent gagal jalan, agent otomatis rollback ke versi terakhir yang sehat lalu melapor error — tidak ada agent mati gara-gara typo config. Dashboard menampilkan status sinkronisasi semua agent: versi config aktif vs desired, dengan indikator drift.

**Canary deploy (mode pro).** Perubahan config besar bisa dirilis bertahap: terapkan ke satu agent atau satu group dulu, pantau, baru roll out ke semua — satu klik dari UI.

Pembaruan **binary agent** mengikuti pola yang sama di fase lanjut (Fase 3): server menyimpan binary bertanda tangan cosign, agent memverifikasi signature sebelum self-update. Tidak pernah ada update tanpa verifikasi kriptografis.

---

## 13. Healthcheck & Self-Monitoring

Sistem keamanan yang berhenti diam-diam lebih berbahaya daripada tidak punya sistem sama sekali, karena memberi rasa aman palsu. DeusWatch memonitor dirinya sendiri di dua sisi:

**Sisi agent: heartbeat.** Setiap agent mengirim heartbeat ringan tiap 30 detik (configurable) lewat koneksi mTLS yang sama — berisi status kolektor, lag buffer, penggunaan CPU/RAM agent, dan versi config aktif. Status agent di dashboard: `online` → `degraded` (heartbeat masuk tapi ada kolektor error / buffer menumpuk) → `disconnected` (3× heartbeat terlewat) → `stale` (offline > 24 jam). Transisi ke `disconnected` otomatis menghasilkan **alert severity `high`** yang dikirim lewat channel notifikasi (bagian 11) — karena agent yang mati bisa berarti dua hal: masalah teknis, atau **penyerang mematikannya untuk menghilangkan jejak**. Agent juga punya watchdog lokal: jika proses kolektor crash, supervisor internal me-restart-nya dan kejadian itu dilaporkan. Saat reconnect, agent mengirim log yang tertahan di buffer disk lokal selama offline (store-and-forward) — tidak ada log hilang karena putus koneksi singkat.

**Sisi server: setiap komponen saling mengawasi.** Semua service (gateway, worker, API) mengekspos endpoint `/healthz` (liveness) dan `/readyz` (dependensi siap: Postgres reachable, NATS connected) yang dipakai Docker healthcheck untuk auto-restart container yang macet. Di atasnya, satu **monitor internal** mengecek metrik vital tiap menit: lag consumer NATS per stream (deteksi worker yang hidup tapi tidak bekerja), laju ingest vs laju tulis ke database, penggunaan disk (terhubung ke janitor bagian 8), status replikasi Postgres, dan keterlambatan job enrichment/LLM. Anomali apapun menjadi alert internal dengan label `deuswatch.label = selfhealth` yang mengalir di pipeline alert yang sama — jadi masalah kesehatan sistem muncul di dashboard dan Telegram persis seperti alert serangan.

**Halaman System Health di UI.** Satu layar ringkas: status semua container, semua agent (dengan peta status), throughput pipeline real-time, dan riwayat insiden kesehatan — sehingga pertanyaan "kenapa log dari server X tidak masuk sejak kemarin?" terjawab dalam lima detik, bukan lewat sesi debugging.

---

## 14. Sustainability & Funding (DIPUTUSKAN)

Jalur donasi: **Saweria** (audiens Indonesia — QRIS/GoPay/OVO, tarik langsung ke rekening bank lokal) + **Ko-fi** (audiens internasional — masuk via PayPal, withdraw ke rekening Indonesia). Keduanya didaftarkan di `.github/FUNDING.yml` agar GitHub menampilkan tombol Sponsor otomatis di repo.

Penempatan di produk dibuat halus, tidak pernah mengganggu workflow analis: link kecil "♥ Support DeusWatch" di footer sidebar dan di halaman About/Settings, plus satu baris di README. Tidak ada popup, banner, atau nag screen dalam bentuk apapun.

Jalur monetisasi jangka panjang jika proyek membesar: model **open-core hosted** — self-host gratis selamanya (AGPL), versi cloud berbayar untuk yang tidak mau kelola server sendiri (model Plausible/Cal.com). Ini salah satu pertimbangan kuat untuk memilih lisensi AGPL-3.0.

---

## 15. Status Keputusan & Langkah Pertama di Claude Code

**Semua keputusan desain final:** nama **DeusWatch** (module Go: `github.com/<username>/deuswatch`), lisensi **AGPL-3.0**, schema log **DCS** (subset ber-penamaan ECS + namespace `deuswatch.*`, bagian 7), target hardware minimum 2 vCPU / 2 GB RAM / 20 GB disk (recommended 2 vCPU / 4 GB / 50 GB; LLM lokal via Ollama di luar hitungan dan butuh 8 GB+ sendiri — itulah alasan desain provider-agnostic), funding Saweria + Ko-fi via `FUNDING.yml`.

**Langkah pertama di Claude Code, berurutan:** (1) init monorepo Go sesuai struktur bagian 5, beserta LICENSE AGPL-3.0, README skeleton, SECURITY.md, dan `.github/FUNDING.yml`; (2) docker-compose skeleton berisi PostgreSQL+TimescaleDB, NATS JetStream, dan satu service Go hello-world; (3) script generate sertifikat mTLS otomatis, lalu buktikan dua service Go saling bicara lewat mTLS; (4) definisikan DCS di `internal/ingest/schema.go` + migrasi SQL pertama (hypertable chunk per-hari); (5) baru setelah fondasi itu hidup, mulai fitur Fase 1 dari agent Linux. Fondasi dulu, fitur kemudian — dan jangan biarkan bagian 7–14 menggoda keluar dari ruang lingkup Fase 1.
