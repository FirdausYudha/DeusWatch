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

**Windows (Scheduled Task, jalankan sebagai Administrator):**
```powershell
.\deploy\agent\install-windows.ps1 -Binary .\dist\deuswatch-agent-windows-amd64.exe -GatewayUrl https://manager:8443
# taruh sertifikat di C:\ProgramData\DeusWatch\certs, lalu:
Start-ScheduledTask -TaskName DeusWatchAgent
```

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
