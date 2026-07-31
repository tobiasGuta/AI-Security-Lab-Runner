# Smoke test script for Windows (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "Running Doctor check..."
.\lab-runner.exe doctor

Write-Host "Listing Projects..."
.\lab-runner.exe projects list

Write-Host "Smoke test passed!"
