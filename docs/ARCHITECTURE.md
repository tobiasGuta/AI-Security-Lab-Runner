# Architecture Overview

## System Architecture

```text
AI client or human operator
        |
        | MCP stdio or CLI
        v
Go sandbox controller (lab-runner)
        |
        | fixed Docker CLI operations
        v
Disposable runner container
        |
        +-- /scratch     writable persistent session volume
        +-- /tmp         writable tmpfs (128m)
        +-- outbound network access
        +-- access to host-published services (host.docker.internal)
        +-- no host filesystem mounts
        +-- no Docker socket
        +-- no target container managed by controller
```

---

## Key Components

1. **Go Sandbox Controller**: Manages session lifecycles, runs fixed `docker` / `docker compose` subcommands, enforces policies, redacts secrets in audit logs.
2. **Hardened Runner Container**: Built from `runner/Dockerfile`. Non-root user `agent` (UID 10001), read-only root filesystem, dropped capabilities (`cap_drop: ALL`), `no-new-privileges:true`.
3. **Symlink-Safe Filesystem Helper (`sandbox-fs`)**: Go binary compiled inside the container image enforcing `/scratch` root containment.
4. **Host Gateway & Loopback Translation**: Route `localhost` / `127.0.0.1` HTTP requests to `host.docker.internal`.
