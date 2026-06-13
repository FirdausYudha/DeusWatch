# ADR 0001 — Strategi Engine Deteksi Sigma

- Status: **Diusulkan** (hasil spike, menunggu keputusan)
- Tanggal: 2026-06-13
- Konteks: design doc bagian 3 (memilih Sigma), bagian 6 (subset rule Fase 1), bagian 10 (dry-run terhadap histori)

## Konteks & masalah

Nilai jual inti DeusWatch bergantung pada Sigma: ribuan rule komunitas + tag MITRE
ATT&CK "gratis". Pertanyaan spike: **bagaimana cara mengevaluasi rule Sigma di
DeusWatch?** Saat ini deteksi hanya berupa satu detektor brute-force *hardcoded*.

## Temuan riset

1. **Engine match in-process (Go).** `markuskont/go-sigma-rule-engine` (+ fork aktif
   2025: runreveal, tufosa) — ~3000 baris, evaluasi per-event berbasis pohon Matcher.
   Cocok untuk rule **single-event**. **Tidak** menangani korelasi/agregasi.
2. **pySigma (SigmaHQ, Python).** Standar emas; meng-*compile* Sigma → query backend
   (Elasticsearch, Splunk, **SQLite**). Backend SQLite (DenizenB/SigmaHQ) dipakai
   **Zircolite** untuk deteksi Sigma murni via SQL. Mendukung agregasi lewat SQL.
3. **Insight terpenting — biaya sebenarnya bukan di engine match, tapi di PEMETAAN
   FIELD.** Rule komunitas ditulis untuk skema spesifik (Sysmon/Windows Event/
   produk tertentu). Memakainya terhadap data ter-normalisasi kita butuh "processing
   pipeline" (taksonomi field) — inilah yang diselesaikan pipeline pySigma, dan yang
   TIDAK diberikan oleh engine match Go. Prototipe kita (`internal/detect/sigma`)
   mengonfirmasi: parsing + kondisi + modifier itu mudah; menyelaraskan field rule ↔
   DCS adalah pekerjaan nyata yang berkelanjutan.
4. **Brute-force SSH adalah rule AGREGASI** (`count() by source.ip > N`) — itulah
   sebabnya kita terpaksa menulis detektor stateful. Engine match single-event tidak
   bisa menggantikannya; agregasi butuh state atau SQL.

## Hasil prototipe (`internal/detect/sigma`)

Evaluator subset (~300 baris) membuktikan kelayakan: mem-parse rule Sigma YAML asli,
mencocokkan terhadap event DCS (lewat `FlattenEvent` ke key ECS dotted), mendukung
modifier `contains/startswith/endswith/re` & kondisi `and/or/not`/`N of them`, serta
mengekstrak MITRE dari tag. Kondisi agregasi sengaja **ditolak** dan diarahkan ke
jalur SQL. Semua ter-cover test.

## Opsi

| Opsi | Isi | Plus | Minus |
|---|---|---|---|
| A. Adopsi fork Go | pakai runreveal/go-sigma-rule-engine | tak reinvent, matang utk single-event | tak ada agregasi; tetap perlu pemetaan field |
| B. Tulis evaluator sendiri | seperti prototipe ini | kontrol penuh, nol dep | melanggar "jangan reinvent"; beban rawat |
| C. pySigma → SQL | compile rule jadi SQL, jalankan periodik di TimescaleDB | agregasi & dry-run histori "gratis"; matang | Python di build-time; latensi = interval; dialek SQLite≠Postgres perlu disesuaikan |
| D. **Hybrid (rekomendasi)** | A untuk real-time single-event + C untuk agregasi/dry-run | menutup kedua kebutuhan design doc | dua jalur untuk dirawat |

## Keputusan yang diusulkan — Hybrid (D)

1. **Real-time single-event**: adopsi fork Go matang (evaluasi `runreveal/
   go-sigma-rule-engine`); prototipe kita jadi cadangan/pembelajaran, bukan produk.
2. **Agregasi & dry-run histori** (bagian 10): jalur SQL ala Zircolite — compile rule
   agregasi via pySigma (offline/CI, bukan runtime) menjadi query yang dijalankan
   periodik terhadap hypertable `events`. Detektor brute-force saat ini adalah
   placeholder jalur ini.
3. **Investasi utama** diarahkan ke **processing pipeline DCS** (pemetaan field +
   kurasi rule yang relevan untuk dataset Fase 1: sshd/auth/web), karena di situ
   letak biaya & nilai sesungguhnya — bukan di engine match.

## Konsekuensi

- Python (pySigma) masuk sebagai dependensi **build/CI**, bukan runtime — tetap selaras
  arsitektur Go single-binary di runtime.
- Perlu mendefinisikan & memelihara taksonomi field DCS sebagai "pipeline" Sigma.
- Detektor brute-force tetap dipakai sampai jalur SQL agregasi siap.

## Langkah berikut bila disetujui

1. Spike kecil: jalankan satu rule agregasi via pySigma→SQL terhadap TimescaleDB.
2. Evaluasi fork Go terpilih dengan 10–20 rule komunitas single-event nyata + pipeline DCS.
3. Putuskan struktur penyimpanan rule (`rules/sigma/`) + loader + versioning (bagian 10).
