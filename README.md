# AI Security Lab Runner (`lab-runner`)

[![CI](https://github.com/ai-security-lab-runner/lab-runner/actions/workflows/ci.yml/badge.svg)](https://github.com/ai-security-lab-runner/lab-runner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**AI Security Lab Runner** (`lab-runner`) is an authorized, defensive-development local execution system written in Go. It enables AI coding assistants, security-analysis agents, IDE plugins, and automation scripts to safely execute commands inside disposable, restricted Docker environments.

---

## Key Security Features

- **No Host Command Execution**: Agent commands NEVER run on the host system.
- **No Docker Socket Access**: The host Docker socket is NEVER exposed to containers.
- **Read-Only Workspace**: Source code is mounted into `/workspace` strictly read-only (`:ro`).
- **Dedicated Writable Directory**: `/scratch` is the only writable persistent directory for agent proof-of-concept scripts.
- **Internal Network Isolation**: Containers communicate on an internal Docker network with no default internet egress.
- **Hardened Runner Container**: Non-root user `agent` (UID 10001), dropped capabilities (`cap_drop: ALL`), and `no-new-privileges:true`.
- **Secret Redaction**: Automatic redaction of sensitive credentials, API keys, and auth headers from JSONL audit logs.

---

## Quick Start

### 1. Build

```powershell
# Windows
.\scripts\build.ps1

# Linux / macOS
./scripts/build.sh
```

### 2. Verify System Readiness

```bash
lab-runner doctor
```

### 3. Usage Example

```bash
# List available lab projects
lab-runner projects list

# Start a lab session
lab-runner start hello-web-lab

# Execute command inside runner container (target reachability check)
lab-runner exec <session-id> -- curl -s http://target:3000/api/info

# Write script to /scratch
lab-runner write <session-id> /scratch/test.py --file ./local-script.py

# Execute Python script inside runner container
lab-runner exec <session-id> -- python3 /scratch/test.py

# Read result
lab-runner read <session-id> /scratch/result.json

# Stop lab session
lab-runner stop <session-id>
```

---

## Documentation Index

- [Architecture](docs/ARCHITECTURE.md)
- [CLI Reference](docs/CLI_REFERENCE.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [Lab Format Specification](docs/LAB_FORMAT.md)
- [MCP Integration Guide](docs/MCP_INTEGRATION.md)
- [Security Model](docs/SECURITY_MODEL.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Windows Setup](docs/WINDOWS_SETUP.md)
- [Linux Setup](docs/LINUX_SETUP.md)
- [macOS Setup](docs/MACOS_SETUP.md)
