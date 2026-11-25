# netio.patchman ajan dosyalarını derler (Windows geliştirme ortamı için).
# Kullanım: powershell -File scripts\build-agent.ps1 [-Version 0.1.0] [-Out dist\agent]
# Sürüm verilmezse depodaki VERSION dosyası kullanılır.
# PATCHMAN_SIGNING_KEY bir imzalama anahtarı dosyasını gösteriyorsa dosyalar
# imzalanır (netio-patchman-server agent-key ile oluşturulur; sunucuda tutmayın).
# Çıktı, sunucunun PATCHMAN_AGENT_DIST_DIR dizininde beklediği biçimdedir.
param(
    [string]$Version = "",
    [string]$Out = "dist\agent"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not $Version) { $Version = (Get-Content -Raw (Join-Path $root "VERSION")).Trim() }
$Out = (New-Item -ItemType Directory -Force $Out).FullName

$env:CGO_ENABLED = "0"
$ldflags = "-s -w -X netio.patchman/internal/version.Version=$Version"
try {
    foreach ($target in @("linux/amd64", "linux/arm64", "windows/amd64")) {
        $os, $arch = $target.Split("/")
        $name = "netio-patchman-agent-$os-$arch"
        if ($os -eq "windows") { $name += ".exe" }
        $env:GOOS = $os
        $env:GOARCH = $arch
        Write-Host "Derleniyor: $name ($Version)"
        go build -trimpath -ldflags $ldflags -o (Join-Path $Out $name) ./cmd/netio-patchman-agent
        if ($LASTEXITCODE -ne 0) { throw "Derleme başarısız: $name" }
        $sum = (Get-FileHash -Algorithm SHA256 (Join-Path $Out $name)).Hash.ToLower()
        [IO.File]::WriteAllText((Join-Path $Out "$name.sha256"), "$sum  $name`n")
    }
    [IO.File]::WriteAllText((Join-Path $Out "version"), "$Version`n")
} finally {
    Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
}
if ($env:PATCHMAN_SIGNING_KEY) {
    go run ./cmd/netio-patchman-server agent-sign -key $env:PATCHMAN_SIGNING_KEY -dir $Out
    if ($LASTEXITCODE -ne 0) { throw "İmzalama başarısız" }
}
Write-Host "Ajan dosyaları hazır: $Out"
Get-ChildItem $Out | Format-Table Name, Length -AutoSize
