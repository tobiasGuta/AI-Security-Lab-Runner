# MCP Integration Guide

`lab-runner` implements Model Context Protocol (MCP) over stdio. It works with any client supporting standard stdio MCP servers (Claude Desktop, IDE extensions, CLI agents, custom MCP clients).

## Generic Client Registration

### Windows Example

```json
{
  "mcpServers": {
    "security-lab-runner": {
      "command": "C:\\Tools\\Lab-Runner\\lab-runner.exe",
      "args": [
        "serve",
        "--config",
        "C:\\Tools\\Lab-Runner\\config.yaml"
      ]
    }
  }
}
```

### Linux / macOS Example

```json
{
  "mcpServers": {
    "security-lab-runner": {
      "command": "/opt/ai-security-lab-runner/lab-runner",
      "args": [
        "serve",
        "--config",
        "/etc/ai-security-lab-runner/config.yaml"
      ]
    }
  }
}
```

## Available MCP Tools

All tools are prefixed with `lab_`:
- `lab_list_projects`
- `lab_start`
- `lab_exec`
- `lab_read_file`
- `lab_write_scratch`
- `lab_status`
- `lab_export_file`
- `lab_reset`
- `lab_stop`
- `lab_get_audit_summary`

## Stdio Protocol Guarantee

Standard output (`stdout`) is reserved strictly for JSON-RPC MCP messages. All diagnostic logs and error details are printed to `stderr`.
