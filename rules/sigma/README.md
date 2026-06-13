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
- **TIDAK didukung**: agregasi (`| count() by ... > N`) → diarahkan ke jalur SQL
  (mis. brute-force ditangani detektor stateful / pySigma→SQL ke depan).

## MITRE & severity otomatis

`tags: [attack.tXXXX, attack.<tactic>]` → `threat.technique.id` + `threat.tactic.name`.
`level:` (informational/low/medium/high/critical) → `event.severity` (0–4).

## Rule saat ini

| Berkas | Deteksi | Bentuk |
|---|---|---|
| `ssh_login_root.yml` | login SSH sukses sebagai root (T1078.003) | field match |
| `ssh_breakin_attempt.yml` | pesan sshd "POSSIBLE BREAK-IN ATTEMPT" (T1595) | keyword |
