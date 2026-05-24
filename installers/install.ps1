#!/usr/bin/env pwsh
#Requires -Version 5.1

$ErrorActionPreference = "Stop"
$LogFile = "$env:TEMP\secret-stripper-install.log"
$ProjectDir = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$Host.UI.RawUI.WindowTitle = "Secret Stripper Installer"

function Write-Animated {
    param([string]$Text, [string]$Color = "White")
    $colorMap = @{ Green = 2; Cyan = 14; Yellow = 14; Red = 12; Blue = 9; White = 15 }
    $c = $colorMap[$Color]
    foreach ($ch in $Text.ToCharArray()) {
        Write-Host $ch -NoNewline -ForegroundColor $c
        Start-Sleep -Milliseconds 1
    }
    Write-Host ""
}

function Write-Spinner {
    param([string]$Message, [ScriptBlock]$Job)
    Write-Host "  " -NoNewline
    $j = Start-Job -ScriptBlock $Job
    $spin = @('⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷')
    $i = 0
    while ($j.State -eq 'Running') {
        Write-Host "`r  $($spin[$i]) $Message..." -ForegroundColor Cyan -NoNewline
        $i = ($i + 1) % $spin.Length
        Start-Sleep -Milliseconds 100
    }
    $result = Receive-Job -Job $j -ErrorAction SilentlyContinue
    Remove-Job -Job $j -ErrorAction SilentlyContinue
    if ($j.State -eq 'Completed') {
        Write-Host "`r  [OK] $Message... done" -ForegroundColor Green
    } else {
        Write-Host "`r  [FAIL] $Message... FAILED" -ForegroundColor Red
        throw "Step failed: $Message"
    }
    return $result
}

function Test-Administrator {
    $p = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Deps {
    if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
        Write-Host "  [~] Installing Rust via rustup..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri "https://win.rustup.rs" -OutFile "$env:TEMP\rustup-init.exe"
        Start-Process -Wait -FilePath "$env:TEMP\rustup-init.exe" -ArgumentList "-y"
        $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
    }
}

function Build-Binary {
    Push-Location $ProjectDir
    try {
        cargo build --release *>> $LogFile
    } finally {
        Pop-Location
    }
    $bin = "$ProjectDir\target\release\secret-stripper.exe"
    if (-not (Test-Path $bin)) { throw "Build failed: $bin not found" }
    return $bin
}

function Install-Binary {
    param([string]$Source)
    $installDir = "$env:ProgramFiles\Secret Stripper"
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Copy-Item $Source "$installDir\secret-stripper.exe" -Force

    $path = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($path -notlike "*$installDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$path;$installDir", "Machine")
    }
    return "$installDir\secret-stripper.exe"
}

function Install-ServiceTask {
    param([string]$BinaryPath)
    $taskName = "Secret Stripper"
    $action = New-ScheduledTaskAction -Execute $BinaryPath -Argument "daemon"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
}

function Run-Setup {
    $bin = "$ProjectDir\target\release\secret-stripper.exe"
    & $bin setup
}

function Show-Summary {
    Write-Host ""
    Write-Host "════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  Secret Stripper installed successfully!" -ForegroundColor Green
    Write-Host "════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Quick start:" -ForegroundColor White
    Write-Host "  secret-stripper menu     - Open interactive menu" -ForegroundColor Cyan
    Write-Host "  secret-stripper daemon   - Start clipboard monitoring" -ForegroundColor Cyan
    Write-Host "  secret-stripper scan     - Scan clipboard once" -ForegroundColor Cyan
    Write-Host "  secret-stripper setup    - Re-run setup wizard" -ForegroundColor Cyan
    Write-Host "  secret-stripper status   - Check service status" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Log file: $LogFile" -ForegroundColor Yellow
    Write-Host ""
}

try {
    Clear-Host
    Write-Animated "   ____ _ _       ____                     _    " "Cyan"
    Write-Animated "  / ___(_) |_    / ___|_   _ _ __ ___  __| |_   " "Cyan"
    Write-Animated " | |   | | __|  | |  _| | | | '__/ _ \/ _\` | | | |" "Cyan"
    Write-Animated " | |___| | |_   | |_| | |_| | | |  __/ (_| | |_| |" "Cyan"
    Write-Animated "  \____|_|\__|   \____|\__,_|_|  \___|\__,_|\__, |" "Cyan"
    Write-Animated "                                            |___/ " "Cyan"
    Write-Host ""
    Write-Animated "  Clipboard PII & Secret Redactor" "Blue"
    Write-Host "  OS: Windows | Log: $LogFile" -ForegroundColor Yellow
    Write-Host ""

    Write-Host "[1] Checking system requirements" -ForegroundColor Cyan
    if (-not (Test-Administrator)) {
        Write-Host "  [~] Not running as Administrator - restart elevated" -ForegroundColor Yellow
    }
    Write-Spinner "Verifying dependencies" { Install-Deps }
    Write-Host "  [OK] Rust toolchain ready" -ForegroundColor Green

    Write-Host "`n[2] Building Secret Stripper (release)" -ForegroundColor Cyan
    $binarySource = Write-Spinner "Compiling Rust binary" { Build-Binary }
    $size = (Get-Item $binarySource).Length / 1KB
    Write-Host "  Binary: ${size}KB" -ForegroundColor Green

    Write-Host "`n[3] Installing binary" -ForegroundColor Cyan
    $binaryPath = Write-Spinner "Copying to Program Files" { Install-Binary -Source $binarySource }

    if (-not (Test-Administrator)) {
        Write-Host "  [~] Service install requires Administrator. Run: secret-stripper install" -ForegroundColor Yellow
    } else {
        Write-Host "`n[4] Installing service" -ForegroundColor Cyan
        Write-Spinner "Configuring auto-start" { Install-ServiceTask -BinaryPath $binaryPath }
    }

    Write-Host "`n[5] Running setup wizard" -ForegroundColor Cyan
    Run-Setup

    Show-Summary
}
catch {
    Write-Host "`nInstallation failed!" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Check log: $LogFile" -ForegroundColor Yellow
    exit 1
}
