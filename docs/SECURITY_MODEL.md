# Security Model

The security model of `AI Security Lab Runner` centers on defense-in-depth and strict isolation for agent operations.

## Core Design Principles

1. **Separation of Target and Runner**: Agent tools execute inside a dedicated runner container, separate from the target container(s).
2. **Read-Only Codebase Mount**: The user's project source code is mounted into `/workspace` read-only (`:ro`).
3. **Dedicated Writable Workspace**: `/scratch` is a isolated Docker volume for writing proof-of-concept scripts and temporary output.
4. **Internal Network Boundary**: Containers run on an internal Docker network with default egress disabled (`internal: true`).
5. **No Host Docker Socket Access**: The Docker daemon socket is NEVER mounted into any container.
6. **No Host Shell Invocation**: Agent commands run ONLY inside the container via fixed `docker compose exec` argument arrays. Host shell processes (`powershell`, `cmd`, `bash`) are never invoked.
7. **Privilege Reduction**: Containers drop all Linux capabilities (`cap_drop: ALL`), enable `no-new-privileges:true`, and run as non-root user `agent` (UID 10001).
8. **Explicit Controlled Exports**: Files can only be exported from `/scratch` when `allow_export` is explicitly enabled in configuration.
