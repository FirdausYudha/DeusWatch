# Agent DeusWatch

Agent (Go single-binary) mengumpulkan log endpoint dan mengirimkannya ke manager
(gateway) lewat **mTLS**. Arsitektur kolektor **berbeda per-OS** (dipilih saat
kompilasi via build tag — mirip agent Wazuh):

| OS | Source default | Kolektor |
|---|---|---|
| Linux | `/var/log/auth.log` (sshd), `/var/log/syslog` | berkas; `journald` via config |
| Windows | Event Log `Security`, `System` | `wineventlog` (Get-WinEvent) |
| lainnya | — | set `LOG_FILE` manual |

Override sumber tunggal kapan saja: `LOG_FILE=/path DATASET=sshd`.

### Tipe source (config push)

| `type` | Arti | `path` |
|---|---|---|
| `file` | tail berkas (lintas-OS) | path berkas |
| `journald` | systemd journal (Linux) | unit (opsional) |
| `wineventlog` | Windows Event Log | nama channel |
| `fim` | **File Integrity Monitoring** (lintas-OS) | berkas/direktori, beberapa dipisah koma |

FIM men-hash (SHA-256) target tiap ~60s; berkas dibuat/diubah/dihapus di-emit sebagai
event DCS `event.category=file` (field `file.path`, `file.hash.sha256`). Atur via
config push, mis. `{"dataset":"fim","type":"fim","path":"/etc/passwd,/etc/ssh/sshd_config"}`.

## Build (cross-compile)

```sh
./scripts/build-agent.sh            # Linux/macOS  -> dist/
.\scripts\build-agent.ps1           # Windows      -> dist\
```
Menghasilkan biner untuk linux/amd64, linux/arm64, windows/amd64, darwin/amd64, darwin/arm64.

## Install

**Linux (systemd):**
```sh
sudo ./deploy/agent/install-linux.sh dist/deuswatch-agent-linux-amd64
sudo nano /etc/deuswatch/agent.env      # set GATEWAY_URL, taruh sertifikat di /etc/deuswatch/certs
sudo systemctl restart deuswatch-agent
```

**Windows (Windows Service native, jalankan sebagai Administrator):**
```powershell
.\deploy\agent\install-windows.ps1 -Binary .\dist\deuswatch-agent-windows-amd64.exe -GatewayUrl https://manager:8443
# taruh sertifikat di C:\ProgramData\DeusWatch\certs, lalu:
& 'C:\Program Files\DeusWatch\deuswatch-agent.exe' -service start
```
Agent terdaftar di SCM sebagai service `DeusWatchAgent` (auto-start, SYSTEM) dengan
recovery restart-on-failure. Sub-perintah: `-service install|uninstall|start|stop`.
Saat config push naik versi, agent keluar dengan kode error agar SCM me-restart &
menerapkan config baru.

## Konfigurasi (env)

| Var | Arti |
|---|---|
| `GATEWAY_URL` | URL manager, mis. `https://manager:8443` |
| `CERT_DIR` | folder berisi `ca.crt`, `client.crt`, `client.key` |
| `HOST_NAME` | nama host dilaporkan (kosong = hostname OS) |
| `LOG_FILE` / `DATASET` | override sumber tunggal (opsional) |
| `FROM_START` | `1` = kirim baris lama juga saat start |

> Enrollment per-agent (token sekali-pakai + sertifikat unik yang bisa dicabut)
> menyusul; saat ini agent memakai sertifikat client dari `CERT_DIR`.
