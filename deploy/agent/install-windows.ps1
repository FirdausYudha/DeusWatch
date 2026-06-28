# Install the DeusWatch agent on Windows as a NATIVE Windows Service (auto-start, SYSTEM).
# Run as Administrator.
#   .\install-windows.ps1 -Binary .\deuswatch-agent-windows-amd64.exe -GatewayUrl https://manager:9443
param(
    [string]$Binary = ".\deuswatch-agent-windows-amd64.exe",
    [string]$GatewayUrl = "https://manager.example:9443",
    [string]$CertDir = "C:\ProgramData\DeusWatch\certs"
)
$ErrorActionPreference = "Stop"

$dest = "C:\Program Files\DeusWatch"
New-Item -ItemType Directory -Force -Path $dest, $CertDir | Out-Null
Copy-Item $Binary "$dest\deuswatch-agent.exe" -Force

# Configuration via machine environment variables (read by the agent at start).
[Environment]::SetEnvironmentVariable("GATEWAY_URL", $GatewayUrl, "Machine")
[Environment]::SetEnvironmentVariable("CERT_DIR", $CertDir, "Machine")

# Install as a native Windows Service (the agent registers itself with the SCM,
# complete with a restart-on-failure recovery action — including when a config push bumps the version).
& "$dest\deuswatch-agent.exe" -service install

Write-Host ""
Write-Host "Agent installed as the Windows Service 'DeusWatchAgent'."
Write-Host "Place the certificates in $CertDir, then run:"
Write-Host "  & '$dest\deuswatch-agent.exe' -service start"
Write-Host "Uninstall: & '$dest\deuswatch-agent.exe' -service uninstall"
