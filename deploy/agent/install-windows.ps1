# Install agent DeusWatch di Windows sebagai Scheduled Task (run saat startup, SYSTEM).
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

$action = New-ScheduledTaskAction -Execute "$dest\deuswatch-agent.exe"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName "DeusWatchAgent" -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Agent terpasang sebagai Scheduled Task 'DeusWatchAgent'."
Write-Host "Letakkan sertifikat di $CertDir, lalu: Start-ScheduledTask -TaskName DeusWatchAgent"
