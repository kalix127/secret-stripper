#Requires -Version 5
$ErrorActionPreference = 'Stop'

# Served verbatim from https://secretstripper.download/install.ps1 - version-agnostic,
# always resolves GitHub's "releases/latest" alias. Upload once.
$Repo = if ($env:SECRET_STRIPPER_REPO) { $env:SECRET_STRIPPER_REPO } else { 'kalix127/secret-stripper' }

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'aarch64' } else { 'x86_64' }
$asset = "secret-stripper-windows-$arch.exe"
$url = "https://github.com/$Repo/releases/latest/download/$asset"

Write-Host "  Secret Stripper Installer" -ForegroundColor Cyan
Write-Host "  Downloading $asset ..." -ForegroundColor Yellow

$dir = Join-Path $env:LOCALAPPDATA 'Programs\secret-stripper'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$bin = Join-Path $dir 'secret-stripper.exe'
$tmpBin = "$bin.download"

try {
    Invoke-WebRequest -Uri $url -OutFile $tmpBin -UseBasicParsing
} catch {
    Write-Host "  Download failed. No release binary for your platform." -ForegroundColor Red
    Write-Host "  Build from source instead: https://rustup.rs"
    exit 1
}

# Verify the downloaded asset against the release's SHA256SUMS. Releases
# that don't publish SHA256SUMS (pre-1.0.0) refuse to install unless the
# user sets SECRET_STRIPPER_SKIP_CHECKSUM=1.
$sumsUrl = "https://github.com/$Repo/releases/latest/download/SHA256SUMS"
$sumsFile = Join-Path $dir 'SHA256SUMS.tmp'
try {
    Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsFile -UseBasicParsing
    $expected = (Get-Content $sumsFile | Where-Object { $_ -match "[\s\*]$([regex]::Escape($asset))$" } | Select-Object -First 1) -split '\s+' | Select-Object -First 1
    Remove-Item $sumsFile -Force
    if (-not $expected) {
        Write-Host "  No SHA256 for $asset in SHA256SUMS." -ForegroundColor Red
        Remove-Item $tmpBin -Force
        exit 1
    }
    $actual = (Get-FileHash $tmpBin -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) {
        Write-Host "  SHA256 mismatch for $asset" -ForegroundColor Red
        Write-Host "  expected: $expected"
        Write-Host "  actual:   $actual"
        Remove-Item $tmpBin -Force
        exit 1
    }
    Write-Host "  Verified SHA256 of $asset" -ForegroundColor Green
} catch {
    if ($env:SECRET_STRIPPER_SKIP_CHECKSUM -eq '1') {
        Write-Host "  SHA256SUMS missing; SECRET_STRIPPER_SKIP_CHECKSUM=1, continuing unverified." -ForegroundColor Yellow
    } else {
        Write-Host "  Could not verify SHA256SUMS. Refusing to install unverified binary." -ForegroundColor Red
        Write-Host "  Override with SECRET_STRIPPER_SKIP_CHECKSUM=1 if you understand the risk."
        Remove-Item $tmpBin -Force -ErrorAction SilentlyContinue
        Remove-Item $sumsFile -Force -ErrorAction SilentlyContinue
        exit 1
    }
}
Move-Item -Force $tmpBin $bin

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$dir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    $env:Path += ";$dir"
}
Write-Host "  Installed to $bin" -ForegroundColor Green

try { & $bin init } catch { Write-Host "  Init had warnings. Run 'secret-stripper menu' to fix." -ForegroundColor Yellow }

Write-Host ""
Write-Host "  Secret Stripper is ready."
Write-Host "  Copy text with Ctrl+C, then press your hotkey to redact it."
Write-Host "  secret-stripper menu    - settings, hotkey, notifications"
Write-Host "  secret-stripper status  - show current state"
