# Install script for Windows (PowerShell)
$ErrorActionPreference = "Stop"

$installDir = "$env:LOCALAPPDATA\Programs\LabRunner"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

Copy-Item -Force lab-runner.exe $installDir\lab-runner.exe
Write-Host "Installed lab-runner to $installDir\lab-runner.exe"
