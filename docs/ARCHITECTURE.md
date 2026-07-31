# AI Security Lab Runner Architecture

## Overview

`AI Security Lab Runner` (`lab-runner`) is a production-quality local execution system written in Go. It enables AI coding assistants and security-analysis agents to safely execute commands inside disposable, locally controlled Docker environments.

```
AI client or human operator
        |
        | MCP stdio or CLI
        v
Go-based AI Security Lab Runner
        |
        | validated and fixed Docker operations
        v
Disposable Docker Compose project
        |
        +-- target container or containers
        |
        +-- dedicated runner container
                |
                +-- /workspace  read-only project source
                +-- /scratch    writable agent workspace
                +-- /tmp        writable temporary filesystem
```

## Security Invariants & Boundaries

1. **Host Shell Prohibition**: Agent commands NEVER execute on the host (no `powershell`, `cmd`, `bash`, `zsh`, or `WSL` host invocation).
2. **Container Execution Only**: Commands execute exclusively inside the runner container (`runner bash -lc "<command>"`).
3. **No Socket Exposure**: Docker socket is NEVER mounted into any container.
4. **Read-Only Workspace**: `/workspace` is mounted read-only (`:ro`).
5. **Restricted Writable Storage**: `/scratch` (dedicated volume) is the only persistent writable workspace. `/tmp` uses tmpfs (128m).
6. **Internal Networking**: Target and runner containers communicate on a private Docker internal network without internet egress by default.
