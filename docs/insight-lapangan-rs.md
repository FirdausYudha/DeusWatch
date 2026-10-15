# Insight Lapangan Rumah Sakit — Gap & Backlog Pengembangan

Hasil diskusi lapangan dengan tim infrastruktur IT rumah sakit, diterjemahkan menjadi daftar
gap yang bisa dikerjakan pada DeusWatch.

| | |
|---|---|
| **Narasumber** | Onsite Engineer / Technical Support dari **PT Buana** (vendor yang menangani infrastruktur, aplikasi, jaringan dan SDM untuk **±20 rumah sakit**, operasional 24 jam) |
| **Sumber** | Transkrip diskusi lapangan, 5 bagian |
| **Status kode** | Setiap baris "Kondisi saat ini" di bawah sudah diverifikasi langsung terhadap kode, bukan asumsi |

---

## Ringkasan gap

| # | Gap | Prioritas | Kondisi di DeusWatch |
|---|---|---|---|
| 1 | Monitoring kesehatan **API/layanan** per-endpoint ("hijau tapi mati") | **P1** | ✅ **Selesai** (v2.51.0) — menu Service Health |
| 2 | **Asset inventory** perangkat keras (ITIL) | **P1** | ✅ **Selesai** (v2.51.0) — kartu aset di menu Inventory |
| 3 | Dukungan **Ruijie** untuk auto-block | P2 | ✅ **Selesai** — responder SSH/CLI generik ([ssh-cli.md](ssh-cli.md)) |
| 4 | Ticketing: alert→tiket, Telegram, **scorecard SLA**, GLPI | P2 | ✅ **Selesai** — alert→tiket, notifikasi, scorecard SLA, dan mirror GLPI (satu arah + tarik status) |
| 5 | **Windows agent** + identitas di workstation bersama (AD) | P2 | Agent Windows parsial; AD/LDAP belum ada |
| 6 | Sensor **IoT & lingkungan** (suhu, kelembapan, finger, CCTV) | P3 | Belum ada |
| 7 | **SNMP** monitoring perangkat jaringan | P3 | ✅ **Selesai** — menu Network ([snmp.md](snmp.md)) |
| 8 | Lateral movement antar container **Kubernetes** | P3 | Deteksi ada, konteks container belum |
| 9 | Multi-tenant untuk **vendor/MSP** (±20 RS satu konsol) | P3 | **Sudah ada** (RLS + workspace) — tinggal diposisikan |
| 10 | Jalur **ISO 27001** (bukti audit) | P3 | Sebagian (audit log) |

---

## Konteks lingkungan nyata

| Aspek | Kondisi di lapangan |
|---|---|
| Perangkat jaringan | **Full Ruijie** (router + switch + access point, satu bundling, kontrak 3–4 tahun). CLI mirip Cisco, tetapi operasional harian lebih banyak lewat GUI. Sebagian fitur (mis. port security) hanya tersedia di CLI |
| Monitoring | Terpecah di beberapa alat: **The Dude** (switch), **WIS Cloud** (access point), **Grafana / Zabbix / Prometheus** (terpusat di kantor Jakarta), pfSense, Wazuh, Trend Micro, Kubernetes |
| Ticketing | **GLPI** (open source, MySQL) dengan kerangka **ITIL** — aset, insiden, project |
| Struktur tim | Technical Support (L1) → NOC / Network / Server (L2–L3) → DevOps & SOC (remote, Jakarta). DBA tim terpisah |
| Kepatuhan | Ada ISO, tetapi beraspek kerumahsakitan (failover, bencana, SOP). **Belum ada ISO 27001 / sertifikasi keamanan.** Tidak memakai COBIT |
| Integrasi eksternal | BPJS, Kemenkes, bank (pembayaran), farmasi — banyak jalur *bridging* |
| Otomasi | Konfigurasi massal switch dilakukan lewat skrip CLI ("kalau harus 10, implementasi 10 kan capek") |

---

## P1 — Prioritas utama

### Gap 1. Monitoring kesehatan API/layanan ("hijau tapi mati")

**Masalah di lapangan.** Ini keluhan operasional yang paling panjang dibahas. Integrasi ke BPJS
sering bermasalah, dan server BPJS turun **tanpa pengumuman resmi** — informasi beredar lewat
grup Telegram tidak resmi yang diteruskan dari orang ke orang, atau baru ketahuan ketika loket
pendaftaran komplain.

> "Di dashboard kita itu ping, ping-nya oke, oke bisa. Tapi ya get-nya oke. Tapi ada beberapa
> kadang edit enggak bisa. Kemudian finger-nya enggak bisa. Hanya service-service itu kan di
> dalam BPJS kan banyak ya. Nah, itu kayaknya harus dijadiin... dipecah-pecah itu service-nya."

> "Dari sisi saya yang infra, 'Oke kok ini internet aman'. Tapi di pendaftaran di loket 'Ini
> enggak bisa'." → miskom antara tim infra dan unit layanan.

Akibatnya: pasien sudah mendaftar lewat Mobile JKN tetapi ditolak karena server JKN mati, lalu
pendaftaran harus dibatalkan manual dari sisi rumah sakit.

**Kondisi saat ini.** ✅ **Selesai di v2.51.0.** Menu **Service Health**: cek HTTP dan TCP per
endpoint, dikelompokkan per fungsi bisnis, dengan tiga aturan (status code, isi body yang
diharapkan, batas latensi), alert saat turun dan pulih, serta timeline 24 jam.

**Yang perlu dibangun.** Monitoring **per-endpoint**, bukan per-host:

- Cek HTTP (metode, header, body opsional) + ICMP, dengan interval yang bisa diatur.
- Rekam **status code dan latency** tiap pemeriksaan, simpan riwayatnya sebagai time series.
- Kelompokkan endpoint per **fungsi bisnis** (pendaftaran, login, cek klaim, finger) sehingga
  layar menjawab "fungsi apa yang sedang mati", bukan sekadar "host hidup".
- Alert saat gagal beruntun atau latency melewati ambang; masuk ke jalur notifikasi yang sudah ada.
- Timeline/riwayat agar pertanyaan "sejak kapan mati" bisa dijawab.

**Kenapa ini bernilai.** Menjawab keluhan yang benar-benar dirasakan setiap hari, dan tidak
terpecahkan oleh Wazuh / The Dude / Grafana yang sudah mereka punya. Bisa didemokan dengan
endpoint simulasi tanpa perlu akses sistem BPJS asli — narasumber sendiri menyarankan
"mungkin dibuat simulasi kali ya".

---

### Gap 2. Asset inventory perangkat keras (ITIL)

**Masalah di lapangan.** Manajemen aset adalah salah satu dari dua modul GLPI yang paling
sering mereka pakai (aset dan insiden/ticketing).

> "Agent-nya buat... kalau dari sisi ITIL kan aset manajemen. Isiannya apa? Komputer, nama
> komputer, merek, terus serial number... kalau nama komputer ditariknya dari hostname. Terus
> kalau serial number, dari Windows itu bisa tariknya pakai Shell, PowerShell, WMIC. IP...
> Merek komputer juga bisa. Jadi lokasinya nanti ketahuan."

**Kondisi saat ini.** ✅ **Selesai di v2.51.0.** Agent mengumpulkan manufacturer, model, serial
number, core CPU, memori, serta IP dan MAC primer; ditampilkan sebagai kartu aset di menu Inventory.
Yang belum: label lokasi yang diisi operator, dan ekspor.

**Yang perlu dibangun.** Kolektor aset di agent yang mengirim: hostname, merek/manufacturer,
model, **serial number**, OS + versi, CPU/RAM, alamat IP/MAC, dan lokasi (label yang bisa diisi
operator). Ditampilkan di halaman Agents dan bisa diekspor.

**Catatan effort.** Paling murah di daftar ini — agent, transport, dan halaman Agents sudah ada;
yang ditambahkan hanya kolektor plus kolom penyimpanan. Teknik pengambilannya pun sudah
ditunjukkan narasumber (PowerShell/WMIC di Windows; `dmidecode` di Linux).

---

## P2 — Penting untuk adopsi nyata

### Gap 3. Dukungan Ruijie untuk auto-block

Seluruh jaringan rumah sakit ini memakai Ruijie, sementara responder DeusWatch hanya mendukung
nftables, MikroTik (REST RouterOS), dan CrowdSec. Artinya **fitur auto-block tidak dapat
menyentuh perangkat edge mereka sama sekali**.

> "Kali ini masih diintegrasikan dengan MikroTik. MikroTik sebenarnya kan dia punya REST API,
> kalau Ruijie enggak... saya kurang tahu."

Ini juga bersinggungan dengan keluhan umum mereka:

> "Yang kesusahan kita itu antar-environment vendor. Misal switch kita biasanya pakai Ruijie,
> terus nanti ada perubahan kontrak, ada Aruba. Nah itu sinkronisasi teknologinya."

**Usulan.** Riset API/CLI Ruijie. Bila tidak ada REST yang memadai, bangun **responder generik
berbasis SSH/CLI** (perintah per-vendor dapat dikonfigurasi) — satu pekerjaan yang sekaligus
menjawab masalah multi-vendor, bukan hanya Ruijie.

**Kondisi saat ini.** ✅ **Selesai.** Integrasi **Network device over SSH**: DeusWatch menyediakan
transport SSH, validasi alamat, dan pinning host key; **perintahnya diisi operator**.

Tidak ada konektor "Ruijie" di dalam produk, dan itu disengaja. Daftar perintah vendor yang
dibundel adalah daftar yang tidak pernah diuji terhadap perangkat, versi firmware, dan konfigurasi
mereka. Ketika salah, ia tidak gagal dengan keras — perintah ditolak, ban tampak berhasil, dan
operator percaya jaringannya terlindungi padahal tidak. Jalur penegakan yang rusak diam-diam lebih
buruk daripada tidak ada sama sekali.

Mekanisme yang sama sekaligus menjawab keluhan multi-vendor mereka: ganti vendor berarti mengubah
empat kolom teks, bukan menunggu rilis baru.

**Bahaya utama yang ditutup:** alamat yang masuk ke baris perintah perangkat berasal dari alert,
jadi dipengaruhi penyerang. "Source IP" berisi `1.2.3.4; reload` akan me-reboot switch inti RS.
Setiap alamat diurai dan **dirender ulang dari hasil penguraian** sebelum masuk template, sehingga
yang sampai ke perangkat selalu alamat kanonik, tidak pernah string aslinya.

---

### Gap 4. Ticketing: alert → tiket, Telegram, dan scorecard SLA

**Masalah di lapangan.** Pengguna enggan mengisi tiket dan memilih mengobrol langsung, sehingga
tim IT mengerjakan pekerjaan ganda.

> "User itu kalau ada troubleshoot paling malas isi ticketing, isi insiden. Jadi dia lebih ke
> chatting. Jadi kita kadang dobel: WhatsApp ya kita terima, tiket ya kita isi sendiri."

Dampaknya bukan sekadar repot — tiket adalah **dasar penilaian kinerja IT** mereka.

> "Solusinya kan kita pengin IT juga ada penilaian... Kita bisa inject misal mau integrasi ke
> chat Telegram. Jadi setiap ada tiket masuk, masuk ke Telegram. Atau ada dashboard-nya, jamnya
> awalnya ini masuk, nanti penyelesaiannya kayak gimana. Nanti bisa jadi rapot."

**Kondisi saat ini.** ✅ **Sebagian selesai.** Yang sudah ada: alert di atas ambang membuka tiket
sendiri (dengan deduplikasi agar satu rule yang menyala terus tidak menguburkan antrean), notifikasi
tiket dibuka/selesai ke Telegram dan email, serta **scorecard SLA** — waktu respons (sampai tiket
dipegang) dan waktu penyelesaian, median dan p90, dipecah per severity dan per penanggap. Semua
dimatikan secara bawaan sampai operator menyalakannya.

**Mirror GLPI** juga sudah ada: tiket DeusWatch didorong ke GLPI, dan status GLPI dibaca balik
([glpi.md](glpi.md)). Sengaja **satu arah untuk isi, baca-saja untuk status** — DeusWatch pemilik
isi tiket, GLPI pemilik sejauh mana pengerjaannya. Tidak ada yang bisa menimpa pekerjaan yang
dilakukan di GLPI, sehingga pertanyaan "siapa menang saat konflik" tidak pernah muncul.

Batas yang disengaja: mengedit teks tiket di DeusWatch **tidak** memperbarui GLPI, dan tiket yang
dibuat manusia di GLPI tidak ditarik masuk. Status **Pending** milik GLPI tidak punya padanan dan
dipetakan ke `in_progress`, karena menyebutnya selesai akan menghentikan jam SLA atas pekerjaan
yang belum selesai.

**Yang perlu dibangun.** Alert otomatis menjadi tiket; notifikasi tiket masuk ke Telegram
(kanal notifikasi sudah tersedia); metrik **waktu respons dan waktu penyelesaian** sebagai
laporan kinerja. Integrasi dua arah dengan GLPI adalah opsi lanjutan (GLPI berbasis MySQL dan
terbuka untuk diintegrasikan).

---

### Gap 5. Windows agent + identitas di workstation bersama

**Masalah di lapangan.** Komputer di *nurse station* dipakai bergantian oleh banyak perawat dan
dokter lintas sif.

> "Nurse station tuh ada beberapa perawat, dokter, sif. Dokter kalau sesuai security itu
> harusnya waktu login Windows memakai login-nya sendiri dan terintegrasi dengan web-nya...
> Nah, itu perlu dimonitoring juga."

Perhatikan sudut pandangnya: ini **audit identitas dan akses rekam medis**, bukan antivirus —
pertanyaannya "siapa yang membuka rekam medis dari PC bersama ini".

Untuk mengelola armada PC, skala enterprise memakai **Active Directory** (instalasi serentak,
manajemen user dan kebijakan).

**Kondisi saat ini.** Agent Windows masih parsial. Tidak ada integrasi Active Directory/LDAP.

**Yang perlu dibangun.** Selesaikan agent Windows lebih dulu, lalu korelasikan login Windows
dengan sesi aplikasi SIMRS. Integrasi Active Directory menyusul.

---

## P3 — Strategis / jangka menengah

### Gap 6. Sensor IoT dan lingkungan

> "Ruangan suhu... batasnya kan 18 derajat sampai 23 dengan kelembapannya 60%. Nah, itu belum
> ada kita, kita pakai yang udah jadi, Bardi. Finger juga kalau mau IoT masuk situ, log
> masuk-keluar. Karena finger juga peraturan dari rumah sakit sama BPJS — akreditasinya: CCTV,
> finger, suhu, APAR, alat kelembapan."

Pendorongnya adalah **akreditasi rumah sakit**, bukan sekadar kenyamanan. Ambang batas dan alarm
(mis. suhu 60°C memicu alarm) sudah menjadi pola kerja mereka. Perangkat yang dipakai (Bardi)
disebut bisa diintegrasikan sendiri.

### Gap 7. SNMP monitoring perangkat jaringan

Mereka menarik sensor SNMP (CPU, suhu, status) tetapi alatnya terpecah: The Dude untuk switch,
WIS Cloud untuk access point, Grafana di pusat. Keinginan mereka eksplisit: satu dashboard
terpusat. Menambahkan SNMP ke DeusWatch menyatukan ketiganya.

**Kondisi saat ini.** ✅ **Selesai.** Menu **Network**: polling SNMP v2c dan v3, board
dikelompokkan per lokasi, uptime dan identitas perangkat, status per port (opsional), serta alert
saat perangkat tidak menjawab dan saat sensor melewati ambang.

**Satu hal yang menentukan desainnya:** SNMP menstandarkan jauh lebih sedikit daripada yang orang
kira. Uptime, identitas perangkat, dan tabel interface sama di semua vendor — itu dibaca otomatis.
Tetapi **CPU, suhu, dan status power supply tidak punya OID standar sama sekali**; setiap vendor
menaruhnya di tempat berbeda. Padahal persis itu yang narasumber sebut.

Jadi sensor CPU dan suhu **didefinisikan operator**: nama, OID, satuan, pengali, dan ambang batas.
Tim sudah menarik nilai-nilai ini lewat The Dude, jadi OID-nya sudah ada di tangan mereka. Ini yang
membuat fitur ini bekerja di Ruijie tanpa saya menebak OID yang tidak bisa diverifikasi — dan tetap
bekerja di Aruba kalau kontraknya berubah.

### Gap 8. Lateral movement antar container Kubernetes

Usulan datang dari narasumber sendiri:

> "Dalam Kubernetes itu kan ada beberapa Docker, setiap Docker itu terhubung bertukar datanya
> lewat API. Nah, dari API itu mungkin bisa dijadiin dashboard, bahwa misal Docker ini melakukan
> login atau create user." → disepakati sebagai pola **lateral movement**.

Deteksi lateral movement sudah menjadi kekuatan DeusWatch; yang belum ada adalah konteks
container/API antar-service.

### Gap 9. Multi-tenant untuk vendor/MSP

> "Dari kantor pusat kan enggak hanya sini aja, kalau di kita Buana ada sekitar 20 rumah sakit.
> Itu 24 jam, jadi ada dashboard-nya sendiri jadi gampang."

**DeusWatch sudah memiliki ini** (multi-tenancy berbasis RLS + workspace). Implikasi penting:
**calon pembeli yang paling masuk akal adalah vendor pengelola seperti PT Buana, bukan satu
rumah sakit** — satu konsol untuk puluhan rumah sakit.

### Gap 10. Jalur ISO 27001

> "Kalau dari security, belum. Karena security sisi IT ya, belum ada ISO."

Peluang: DeusWatch dapat menjadi penyedia bukti audit (log akses, kontrol, laporan berkala)
untuk organisasi yang hendak mengejar sertifikasi keamanan.

---

## Catatan teknis dari sesi demo

- **Skala belum terbukti.** Narasumber bertanya langsung "udah pernah nyoba sampai maksimal
  berapa? Biasanya kalau kantoran 50, 100", agar bisa memperkirakan spesifikasi server. Saat ini
  DeusWatch baru diuji pada **satu host**, dan angka sizing (4 core / 8 GB untuk 100 agent;
  8 core / 16 GB untuk 100–1000) masih perkiraan. **Perlu uji beban dan dokumen sizing resmi.**
- **Latensi asisten AI.** Pada demo, jawaban asisten lambat karena memakai Ollama dengan model
  kecil (Llama 1B). Sebagian sudah dijawab oleh dokumen rekomendasi model
  ([llm-providers.md](llm-providers.md) §3); sisanya adalah soal memilih tier model yang tepat.
- **Spesifikasi agent ringan** sudah menjadi nilai jual yang disambut baik (Go native, konsumsi
  "enggak berasa" saat hanya menjalankan agent).

## Di luar lingkup

- **Memperbaiki BPJS itu sendiri.** Di luar kendali rumah sakit maupun DeusWatch. Yang dapat
  dibangun hanyalah deteksi dan visibilitasnya (Gap 1).
- **Mengganti vendor atau perangkat jaringan.** Terkunci kontrak 3–4 tahun.

---

## Rekomendasi urutan kerja

1. ✅ **Gap 1 — API/Service Health Monitoring** (v2.51.0). Dampak tertinggi: masalahnya harian dan
   nyata, tidak terpecahkan oleh perkakas yang sudah ada, dan dapat didemokan dengan endpoint simulasi.
2. ✅ **Gap 2 — Asset inventory** (v2.51.0). Pendamping murah dan cepat; melengkapi sisi ITIL.
3. ✅ **Gap 4 — Ticketing: alert→tiket, notifikasi, scorecard SLA, dan mirror GLPI.** Menjawab
   motif yang disebut narasumber sendiri: tiket sebagai dasar penilaian kinerja IT — dan menaruh
   tiket itu di GLPI, tempat mereka memang sudah bekerja.

**Berikutnya.** Dua kandidat yang tersisa di P2, keduanya butuh akses yang belum ada di sini:

- **Gap 3 — responder SSH/CLI generik** untuk Ruijie dan perangkat multi-vendor. Nilai tertinggi
  yang tersisa (auto-block saat ini tidak menyentuh edge device mereka sama sekali), tetapi template
  perintahnya tidak bisa diverifikasi tanpa perangkat asli.
- **Gap 5 — agent Windows + Active Directory.** Paling besar; butuh host Windows dan domain
  controller untuk pengujian yang berarti.

4. ✅ **Gap 7 — SNMP monitoring.** Mengikuti pola prober Gap 1. Menyatukan The Dude, WIS Cloud,
   dan Grafana jadi satu board, dengan sensor CPU/suhu yang didefinisikan operator karena SNMP
   tidak menstandarkan keduanya.

5. ✅ **Gap 3 — responder SSH/CLI generik.** Hambatan "tidak bisa memverifikasi perintah Ruijie
   tanpa perangkat" larut dengan pola yang sama seperti SNMP: operator yang mengisi bagian
   vendor-spesifik, dan tidak ada satu pun perintah tebakan di dalam produk.

Yang tersisa: **Gap 5** (butuh host Windows dan domain controller), **Gap 8** (butuh klaster
Kubernetes), **Gap 6** (sensor IoT/Bardi — perlu keputusan protokol lebih dulu), **Gap 9** (sudah
ada, tinggal diposisikan dalam materi penjualan), dan **Gap 10** (ISO 27001 — pekerjaan
dokumentasi, bukan kode).
