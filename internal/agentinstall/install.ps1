# DeusWatch agent one-line installer (Windows). Run in an ELEVATED PowerShell:
#   $env:MANAGER='<ip>'; $env:TOKEN='<token>'; $env:NAME='<name>'; iwr http://<ip>:8080/api/agent/install.ps1 -UseBasicParsing | iex
$ErrorActionPreference = 'Stop'

$Manager = $env:MANAGER
$Token   = $env:TOKEN
$Name    = if ($env:NAME) { $env:NAME } else { $env:COMPUTERNAME }
if (-not $Manager -or -not $Token) { throw "Set MANAGER and TOKEN environment variables first" }
$apiPort = if ($env:API_PORT) { $env:API_PORT } else { '8080' }
$gwPort  = if ($env:GW_PORT)  { $env:GW_PORT }  else { '8443' }
$api = "http://${Manager}:$apiPort"
$gw  = "https://${Manager}:$gwPort"

$dest  = 'C:\Program Files\DeusWatch'
$certs = 'C:\ProgramData\DeusWatch\certs'
New-Item -ItemType Directory -Force -Path $dest, $certs | Out-Null

Write-Host "DeusWatch: installing agent '$Name' -> $gw"

# Best-effort: allow outbound to the manager through Windows Firewall.
try {
  New-NetFirewallRule -DisplayName 'DeusWatch agent (outbound)' -Direction Outbound -Action Allow `
    -Protocol TCP -RemotePort $apiPort, $gwPort -ErrorAction SilentlyContinue | Out-Null
} catch {}

# Stop & remove any existing service first, so re-installing can overwrite the running
# .exe (a locked binary makes the download fail) and '-service install' doesn't error
# on an already-installed service. Makes re-install idempotent.
if (Get-Service -Name 'DeusWatchAgent' -ErrorAction SilentlyContinue) {
  Write-Host "DeusWatch: stopping existing agent service for re-install"
  Stop-Service -Name 'DeusWatchAgent' -Force -ErrorAction SilentlyContinue
  if (Test-Path "$dest\deuswatch-agent.exe") {
    try { & "$dest\deuswatch-agent.exe" -service uninstall | Out-Null } catch {}
  }
  Start-Sleep -Seconds 2  # let the SCM release the .exe lock
}

Invoke-WebRequest "$api/api/agent/binary/windows/amd64" -OutFile "$dest\deuswatch-agent.exe" -UseBasicParsing

# Enroll: exchange the one-time token for a unique client certificate.
& "$dest\deuswatch-agent.exe" -enroll -token $Token -name $Name -manager $api -out $certs

# Configuration via machine environment variables (read by the service at start).
[Environment]::SetEnvironmentVariable('GATEWAY_URL', $gw, 'Machine')
[Environment]::SetEnvironmentVariable('CERT_DIR', $certs, 'Machine')

# Install + start as a native Windows Service (auto-start, restart on failure).
& "$dest\deuswatch-agent.exe" -service install
& "$dest\deuswatch-agent.exe" -service start
Write-Host "DeusWatch: agent '$Name' installed & started (service 'DeusWatchAgent')"
