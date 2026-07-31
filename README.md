# AI Security Lab Runner (lab-runner)

[![CI](https://github.com/tobiasGuta/AI-Security-Lab-Runner/actions/workflows/ci.yml/badge.svg)](https://github.com/tobiasGuta/AI-Security-Lab-Runner/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.24-blue.svg)](https://go.dev)
[![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)](https://www.docker.com)

**AI Security Lab Runner** is a generic, network-enabled AI execution sandbox system. It enables AI coding assistants, security-analysis agents, and human developers to safely execute commands, run tools, and make HTTP requests inside disposable, hardened local Docker environments.

---

## Key Features

- **No Project Declarations**: Ask your AI assistant to run `curl https://example.com` or test `http://localhost:3000/api` immediately—no `labrunner.yaml`, project imports, or target container definitions required.
- **Outbound Internet Access**: Direct, controlled network access to public web destinations and APIs.
- **Host-Local Application Access**: Connect to applications already running on your host machine (e.g. `http://localhost:3000`) through `host.docker.internal` mapping.
- **One-Shot & Persistent Workflows**: Supports one-shot ephemeral executions (`sandbox_run`) and persistent stateful sessions (`sandbox_start`, `sandbox_exec`, `sandbox_http_request`).
- **Hardened Runner Environment**: Non-root user (`agent` UID 10001), read-only root filesystem, dropped Linux capabilities (`cap_drop: ALL`), `no-new-privileges`, dedicated `/scratch` volume, tmpfs `/tmp`.
- **Symlink-Safe Filesystem Operations**: Embedded `sandbox-fs` helper prevents symlink escapes outside `/scratch`.
- **MCP Protocol Native**: Stdio server exposing 10 `sandbox_*` tools for any MCP-compatible AI client (Claude, Gemini, OpenAI, IDE agents, custom automation).

---

## Quickstart

### 1. Build the Binary & Runner Image

```powershell
# Build lab-runner executable
go build -o lab-runner.exe ./cmd/lab-runner

# Build runner container image
docker build -t ai-security-agent-runner:latest -f runner/Dockerfile runner/
```

### 2. Verify Infrastructure

```powershell
.\lab-runner.exe doctor
```

### 3. Run a One-Shot Command

```powershell
.\lab-runner.exe sandbox run -- curl -s https://example.com
```

### 4. Make an HTTP Request to a Host-Published Service

```powershell
.\lab-runner.exe sandbox request --url http://localhost:3000/api/info --method GET
```

---

## MCP Integration

Configure your MCP client (e.g., Claude Desktop, Antigravity, VS Code MCP extension):

```json
{
  "mcpServers": {
    "ai-security-sandbox": {
      "command": "D:\\Tools\\Lab-Runner\\lab-runner.exe",
      "args": ["serve"]
    }
  }
}
```

### Available MCP Tools

| Tool | Purpose |
| :--- | :--- |
| `sandbox_run` | One-shot command in a disposable container with auto-cleanup |
| `sandbox_start` | Start persistent sandbox session |
| `sandbox_exec` | Execute command in active sandbox session |
| `sandbox_http_request` | Structured HTTP request with automatic loopback translation |
| `sandbox_write_file` | Symlink-safe file write strictly beneath `/scratch` |
| `sandbox_read_file` | Symlink-safe file read strictly beneath `/scratch` |
| `sandbox_status` | Query active session status |
| `sandbox_stop` | Stop session and destroy runner containers & volume |
| `sandbox_reset` | Recreate sandbox session with same policy |
| `sandbox_get_audit_summary` | Retrieve redacted audit log events |

---

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [CLI Reference](docs/CLI_REFERENCE.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [MCP Integration Guide](docs/MCP_INTEGRATION.md)
- [Network Access & Host Gateway](docs/NETWORK_ACCESS.md)
- [Security & Threat Model](docs/SECURITY_MODEL.md)
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md)
