# Rule Sigma DeusWatch

Folder ini berisi rule deteksi format **Sigma** yang dimuat worker saat start
(`RULES_DIR`, default `rules/sigma`). Worker mengevaluasi tiap event normalized
terhadap rule di sini, di samping detektor brute-force bawaan.

> Status engine: evaluator subset (`internal/detect/sigma`) sebagai **interim** di
> balik antarmuka `detect.Detector` — lihat [ADR 0001](../../docs/adr/0001-sigma-detection-engine.md).

## Taksonomi field (pipeline pemetaan)

Event DeusWatch memakai penamaan **ECS** (lihat DCS, design doc bagian 7). Tulis
rule memakai key ECS dotted ini:

| Field rule | Contoh | Asal |
|---|---|---|
| `event.dataset` | `sshd` | sumber log |
| `event.action` | `ssh_login` | aksi |
| `event.outcome` | `success` / `failure` | hasil |
| `source.ip`, `source.port` | `203.0.113.10` | sumber |
| `user.name` | `root` | akun target |
| `process.name`, `process.command_line` | | endpoint (Fase 2+) |
| `event.original` | baris log mentah | dipakai rule **keywords** |

**Alias** untuk kompatibilitas rule komunitas (di-resolve otomatis,
case-insensitive — lihat `internal/detect/sigma/mapping.go`):
`User`/`username`→`user.name`, `src_ip`/`SourceIp`→`source.ip`,
`CommandLine`→`process.command_line`, `Image`→`process.name`,
`Computer`/`hostname`→`host.name`. Tambah entri saat mengadopsi rule baru.

## Bentuk detection yang didukung

- **Field match**: `selection: { field: nilai }` atau `field: [a, b]` (OR).
  Modifier: `|contains`, `|startswith`, `|endswith`, `|re`.
- **Keyword**: `selection: [ 'string1', 'string2' ]` → cocok substring di isi event
  (terutama `event.original`). Cocok untuk rule Linux berbasis pesan log.
- **Condition**: `and` / `or` / `not`, tanda kurung, `N of them`, `all of <prefix>*`.

## Rule AGREGASI (jalur SQL)

Rule dengan kondisi ber-pipa — `selection | count() [by <field>] <op> N` — tidak bisa
dijawab satu event; ia di-**compile ke SQL** dan dijalankan periodik oleh worker
terhadap hypertable `events` (model Zircolite/pySigma, [ADR 0001](../../docs/adr/0001-sigma-detection-engine.md)).
Ini menggantikan detektor brute-force hardcoded dengan rule berformat Sigma.

- Letakkan di sub-folder `rules/sigma/agg/` (dimuat rekursif satu level; bisa juga
  di root — pemisahan single-event vs agregasi otomatis dari ada/tidaknya `|`).
- **Pipa didukung**: `count()` dengan `by <field>` opsional, operator `> >= < <=`.
- **`timeframe`** (mis. `1m`, `5m`, `1h`, `1d`) = jendela waktu; default 5m.
- **Kiri pipa**: ekspresi boolean atas selection (`and`/`or`/`not`/kurung + nama
  selection). `N of them` **tidak** didukung di sisi kiri pipa.
- Setiap field yang dipakai harus punya kolom DCS yang dipetakan
  (`fieldColumns` di `internal/detect/sigma/aggregate.go` — cermin SQL dari
  `FlattenEvent`). Nilai literal selalu lewat argumen ber-parameter (anti-injeksi).
- Tiap grup yang melewati ambang memicu satu alert; ada **cooldown** per (rule, grup)
  agar serangan panjang tidak membanjiri alert. Tersedia juga **dry-run** terhadap
  histori (`AggregateRunner.DryRun`).

## MITRE & severity otomatis

`tags: [attack.tXXXX, attack.<tactic>]` → `threat.technique.id` + `threat.tactic.name`.
`level:` (informational/low/medium/high/critical) → `event.severity` (0–4).

## Rule saat ini

| Berkas | Deteksi | Bentuk |
|---|---|---|
| `ssh_login_root.yml` | login SSH sukses sebagai root (T1078.003) | field match |
| `ssh_breakin_attempt.yml` | pesan sshd "POSSIBLE BREAK-IN ATTEMPT" (T1595) | keyword |
| `sshd_invalid_user.yml` | upaya login untuk user tak dikenal (T1110.003) | keyword |
| `sshd_failed_root.yml` | kegagalan SSH menargetkan root (T1110) | field match (multi-selection) |
| `agg/ssh_bruteforce.yml` | brute force: >5 kegagalan/IP per 1m (T1110) | **agregasi (SQL)** |
| `agg/ssh_invalid_user_burst.yml` | >10 "invalid user"/IP per 5m (T1110.003) | **agregasi (SQL)** |
