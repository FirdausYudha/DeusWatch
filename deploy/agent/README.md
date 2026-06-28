# DeusWatch agent

The agent (a single Go binary) collects endpoint logs and ships them to the manager
(gateway) over **mTLS**. The collector architecture is **per-OS** (chosen at compile time
via build tags — similar to the Wazuh agent):

| OS | Default sources | Collector |
|---|---|---|
| Linux | `/var/log/auth.log` (sshd), `/var/log/syslog` | file; `journald` via config |
| Windows | Event Log `Security`, `System` | `wineventlog` (Get-WinEvent) |
| other | — | set `LOG_FILE` manually |

Override to a single source any time: `LOG_FILE=/path DATASET=sshd`.

### Source types (config push)

| `type` | Meaning | `path` |
|---|---|---|
| `file` | tail a file (cross-OS) | file path |
| `journald` | systemd journal (Linux) | unit (optional) |
| `wineventlog` | Windows Event Log | channel name |
| `fim` | **File Integrity Monitoring** (cross-OS) | file/directory, comma-separated for multiple |

FIM hashes (SHA-256) the targets every ~60s; created/modified/deleted files are emitted as
DCS events with `event.category=file` (fields `file.path`, `file.hash.sha256`). Configure via
config push, e.g. `{"dataset":"fim","type":"fim","path":"/etc/passwd,/etc/ssh/sshd_config"}`.

## Build (cross-compile)

```sh
./scripts/build-agent.sh            # Linux/macOS  -> dist/
.\scripts\build-agent.ps1           # Windows      -> dist\
```
Produces binaries for linux/amd64, linux/arm64, windows/amd64.

## Install

**Linux (systemd):**
```sh
sudo ./deploy/agent/install-linux.sh dist/deuswatch-agent-linux-amd64
sudo nano /etc/deuswatch/agent.env      # set GATEWAY_URL, put certs in /etc/deuswatch/certs
sudo systemctl restart deuswatch-agent
```

**Windows (native Windows Service, run as Administrator):**
```powershell
.\deploy\agent\install-windows.ps1 -Binary .\dist\deuswatch-agent-windows-amd64.exe -GatewayUrl https://manager:8443
# put certs in C:\ProgramData\DeusWatch\certs, then:
& 'C:\Program Files\DeusWatch\deuswatch-agent.exe' -service start
```
The agent registers in the SCM as the `DeusWatchAgent` service (auto-start, SYSTEM) with
restart-on-failure recovery. Sub-commands: `-service install|uninstall|start|stop`.
When a config push bumps the version, the agent exits with an error code so the SCM
restarts it & applies the new config.

## Configuration (env)

| Var | Meaning |
|---|---|
| `GATEWAY_URL` | manager URL, e.g. `https://manager:8443` |
| `CERT_DIR` | folder containing `ca.crt`, `client.crt`, `client.key` |
| `HOST_NAME` | reported host name (empty = OS hostname) |
| `LOG_FILE` / `DATASET` | single-source override (optional) |
| `FROM_START` | `1` = also send old lines at start |

> Per-agent enrollment (one-time token + revocable unique certificate) is implemented;
> see the main flow in [progress.md](../../progress.md). The agent uses the client cert in `CERT_DIR`.
