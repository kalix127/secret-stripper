#!/usr/bin/env pwsh

$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "  Secret Stripper Uninstaller" -ForegroundColor Cyan
Write-Host ""

Write-Host "  [~] Removing scheduled task..." -ForegroundColor Yellow
Unregister-ScheduledTask -TaskName "Secret Stripper" -Confirm:$false 2>$null

Write-Host "  [~] Removing startup shortcut..." -ForegroundColor Yellow
$startup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Remove-Item "$startup\Secret Stripper.lnk" -Force 2>$null
Remove-Item "$startup\Secret Stripper.vbs" -Force 2>$null

Write-Host "  [~] Removing binary..." -ForegroundColor Yellow
Remove-Item "$env:ProgramFiles\Secret Stripper" -Recurse -Force 2>$null

Write-Host "  [~] Removing config..." -ForegroundColor Yellow
Remove-Item "$env:APPDATA\secret-stripper" -Recurse -Force 2>$null

$path = [Environment]::GetEnvironmentVariable("Path", "Machine")
$newPath = ($path.Split(';') | Where-Object { $_ -ne "$env:ProgramFiles\Secret Stripper" }) -join ';'
[Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")

Write-Host ""
Write-Host "  [OK] Secret Stripper has been removed." -ForegroundColor Green
Write-Host ""
