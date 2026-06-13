# Install agent DeusWatch di Windows sebagai Windows Service NATIVE (auto-start, SYSTEM).
# Jalankan sebagai Administrator.
#   .\install-windows.ps1 -Binary .\deuswatch-agent-windows-amd64.exe -GatewayUrl https://manager:8443
param(
    [string]$Binary = ".\deuswatch-agent-windows-amd64.exe",
    [string]$GatewayUrl = "https://manager.example:8443",
    [string]$CertDir = "C:\ProgramData\DeusWatch\certs"
)
$ErrorActionPreference = "Stop"

$dest = "C:\Program Files\DeusWatch"
New-Item -ItemType Directory -Force -Path $dest, $CertDir | Out-Null
Copy-Item $Binary "$dest\deuswatch-agent.exe" -Force

# Konfigurasi via environment variable mesin (dibaca agent saat start).
[Environment]::SetEnvironmentVariable("GATEWAY_URL", $GatewayUrl, "Machine")
[Environment]::SetEnvironmentVariable("CERT_DIR", $CertDir, "Machine")

# Pasang sebagai Windows Service native (agent mendaftarkan dirinya ke SCM,
# lengkap dengan recovery action restart-on-failure — termasuk saat config push naik).
& "$dest\deuswatch-agent.exe" -service install

Write-Host ""
Write-Host "Agent terpasang sebagai Windows Service 'DeusWatchAgent'."
Write-Host "Letakkan sertifikat di $CertDir, lalu jalankan:"
Write-Host "  & '$dest\deuswatch-agent.exe' -service start"
Write-Host "Uninstall: & '$dest\deuswatch-agent.exe' -service uninstall"
