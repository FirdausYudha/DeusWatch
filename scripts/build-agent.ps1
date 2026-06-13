# Cross-compile agent DeusWatch untuk berbagai OS/arch ke dist\.
#   .\scripts\build-agent.ps1
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
Push-Location $root
try {
    New-Item -ItemType Directory -Force -Path dist | Out-Null
    $targets = @("linux/amd64", "linux/arm64", "windows/amd64", "darwin/amd64", "darwin/arm64")
    foreach ($t in $targets) {
        $os, $arch = $t.Split("/")
        $ext = if ($os -eq "windows") { ".exe" } else { "" }
        $out = "dist/deuswatch-agent-$os-$arch$ext"
        $env:CGO_ENABLED = "0"; $env:GOOS = $os; $env:GOARCH = $arch
        go build -trimpath -ldflags="-s -w" -o $out ./cmd/agent
        Write-Host "built $out"
    }
    Write-Host "Selesai. Biner agent ada di dist\."
} finally {
    Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}
