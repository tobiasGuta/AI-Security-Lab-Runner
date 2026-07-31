# Troubleshooting Guide

## Common Issues & Solutions

### 1. `lab-runner doctor` reports Docker daemon unavailable
- **Cause**: Docker Desktop or Docker Engine service is stopped.
- **Fix**: Start Docker Desktop or execute `sudo systemctl start docker`.

### 2. Linux Containers check fails on Windows
- **Cause**: Docker Desktop is set to Windows Containers mode.
- **Fix**: Right-click Docker Desktop tray icon -> select "Switch to Linux containers...".

### 3. Read-only workspace error during agent command
- **Cause**: Command attempted to modify files under `/workspace`.
- **Fix**: Designate `/scratch` for writing temporary output or script files. `/workspace` is intentionally mounted read-only for host security.

### 4. MCP client fails to connect
- **Cause**: Path escaping issues or non-protocol output on stdout.
- **Fix**: Check `configs/mcp-client-windows.example.json` for proper backslash escaping (`C:\\Tools\\Lab-Runner\\lab-runner.exe`). Verify logs on `stderr`.
