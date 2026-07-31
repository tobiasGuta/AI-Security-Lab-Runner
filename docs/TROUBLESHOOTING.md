# Troubleshooting Guide

## Common Issues & Solutions

### 1. `configuration version 1 is obsolete`
**Cause**: Using a legacy version 1 `config.yaml` containing `lab_root`.
**Solution**: Remove `lab_root` and update schema to version 2 (see `configs/config.example.yaml`).

### 2. `Docker is configured for 'windows' containers`
**Cause**: Docker Desktop is set to Windows container mode.
**Solution**: Right-click Docker Desktop system tray icon -> "Switch to Linux containers...".

### 3. `host.docker.internal not resolving`
**Cause**: Linux Docker Engine without host-gateway configured.
**Solution**: Ensure `extra_hosts: ["host.docker.internal:host-gateway"]` is enabled in configuration version 2.

### 4. Diagnostic Command
Always run `lab-runner doctor` to verify system health:
```powershell
.\lab-runner.exe doctor
```
