# CLI Reference

The compiled binary `lab-runner` exposes subcommands for human operators and CLI-based automation.

## Commands

### `lab-runner serve [--config <path>]`
Starts the MCP stdio server.
- Standard input reads JSON-RPC 2.0 requests.
- Standard output receives ONLY protocol messages.
- Standard error receives diagnostics and logs.

### `lab-runner doctor [--json]`
Checks environment readiness, Docker daemon connectivity, Compose v2 availability, path safety, and active session health.

### `lab-runner projects list [--json]`
Lists discovered lab environments under `lab_root`.

### `lab-runner start <project-name> [--rebuild] [--json]`
Starts disposable target and runner containers for the specified lab project.

### `lab-runner exec <session-id> [--cwd <path>] [--timeout <sec>] [--json] -- <command...>`
Executes a command inside the runner container.

### `lab-runner read <session-id> <container-path> [--max-bytes <n>]`
Reads file content from `/workspace` or `/scratch` inside the runner container.

### `lab-runner write <session-id> <scratch-path> [--file <path>] [--stdin] [--overwrite]`
Writes content to a file strictly under `/scratch` in the runner container.

### `lab-runner status [session-id] [--json]`
Displays active session state and health status.

### `lab-runner export <session-id> <scratch-path> [destination-name]`
Exports a regular file from `/scratch` to the host export directory (when enabled by global configuration).

### `lab-runner reset <session-id> [--rebuild]`
Destroys session containers/volumes and recreates them from manifest.

### `lab-runner stop <session-id>`
Stops session containers and removes disposable resources.

### `lab-runner cleanup [--stale] [--all-owned] [--dry-run]`
Removes application-owned Docker resources identified by `ai.security.lab-runner.managed=true`.

### `lab-runner version [--json]`
Displays application version, Go runtime version, commit, and schema versions.
