# Kebijakan Keamanan DeusWatch

DeusWatch adalah perangkat keamanan. Kami memperlakukan kerentanan dengan sangat serius
dan menghargai laporan yang bertanggung jawab dari komunitas.

## Versi yang didukung

Selama Fase pengembangan awal, hanya branch `main` (terbaru) yang menerima perbaikan keamanan.
Tabel ini akan diperbarui saat rilis ber-versi mulai dipublikasikan.

| Versi | Didukung |
|---|---|
| `main` (pra-rilis) | ✅ |

## Melaporkan kerentanan

**Jangan** membuka GitHub Issue publik untuk kerentanan keamanan.

Sebagai gantinya, gunakan salah satu jalur privat berikut:

1. **GitHub Security Advisory** — fitur "Report a vulnerability" pada tab *Security* repo ini
   (jalur yang lebih disukai).
2. **Email** — `security@deuswatch.example` *(TODO: ganti dengan kontak asli sebelum rilis publik)*.

Sertakan jika memungkinkan:

- Deskripsi kerentanan dan dampaknya.
- Langkah reproduksi atau proof-of-concept.
- Komponen/berkas yang terpengaruh dan versi/commit.
- Saran mitigasi (opsional).

## Yang bisa Anda harapkan

- **Konfirmasi penerimaan** dalam 72 jam.
- **Penilaian awal** dalam 7 hari.
- Pembaruan berkala hingga masalah selesai.
- Kredit kepada pelapor di catatan rilis (kecuali Anda meminta anonim).

## Komitmen secure-by-design

Prinsip keamanan ini berlaku sejak commit pertama dan tidak dikompromikan demi kemudahan:

- **mTLS wajib** untuk seluruh komunikasi agent–server (tanpa mode plaintext, bahkan dev).
- **RBAC + audit log append-only** sejak hari pertama.
- **Secrets terenkripsi** (envelope encryption); tidak pernah muncul di log, di-mask di UI.
- **Parameterized query** tanpa pengecualian; semua log masuk diperlakukan sebagai data berbahaya.
- **Output LLM tidak pernah dieksekusi otomatis** sebagai aksi blocking — konten log adalah
  vektor prompt injection; rekomendasi selalu butuh konfirmasi manusia.
- **Supply chain**: binary & image ditandatangani (cosign); CI menjalankan `govulncheck`,
  `gosec`, dan dependency scanning; SBOM di-generate tiap rilis.

Terima kasih telah membantu menjaga DeusWatch dan penggunanya tetap aman.
