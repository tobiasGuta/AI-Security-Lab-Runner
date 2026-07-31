# Windows 11 Setup Guide

## Requirements
- Windows 11 Home/Pro/Enterprise
- Docker Desktop with WSL2 backend (Linux containers active)
- Go 1.24+ (for building from source)

## Installation & Setup

1. Open PowerShell in repository root `D:\Tools\Lab-Runner`.
2. Build the runner binary and Docker image:
   ```powershell
   .\scripts\build.ps1
   ```
3. Run diagnostic check:
   ```powershell
   .\lab-runner.exe doctor
   ```
4. Register `lab-runner.exe` with your MCP client using `configs/mcp-client-windows.example.json`.
