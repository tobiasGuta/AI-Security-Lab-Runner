# MCP Integration Guide

## Standard I/O MCP Configuration

### Windows
```json
{
  "mcpServers": {
    "ai-security-sandbox": {
      "command": "D:\\Tools\\Lab-Runner\\lab-runner.exe",
      "args": ["serve"],
      "env": {
        "LAB_RUNNER_STATE_DIR": "C:\\Users\\ExampleUser\\.ai-security-lab-runner"
      }
    }
  }
}
```

### Linux / macOS
```json
{
  "mcpServers": {
    "ai-security-sandbox": {
      "command": "/usr/local/bin/lab-runner",
      "args": ["serve"],
      "env": {
        "LAB_RUNNER_STATE_DIR": "/home/user/.ai-security-lab-runner"
      }
    }
  }
}
```

---

## Exposed MCP Tools (`sandbox_*`)

- `sandbox_run`
- `sandbox_start`
- `sandbox_exec`
- `sandbox_http_request`
- `sandbox_write_file`
- `sandbox_read_file`
- `sandbox_status`
- `sandbox_stop`
- `sandbox_reset`
- `sandbox_get_audit_summary`
