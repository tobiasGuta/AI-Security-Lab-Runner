# Threat Model

## Assets

- Host filesystem and host configuration
- Host Docker daemon
- Project source code mounted in `/workspace`
- Agent scratch artifacts in `/scratch`
- Audit log records
- Session state metadata

## Trust Boundaries

- AI Client <---> Controller (`lab-runner` process over MCP stdio)
- Controller <---> Docker CLI (`exec.CommandContext`)
- Host Controller <---> Runner Container (`docker compose exec`)
- Runner Container <---> Target Container (Internal Docker Network)

## Attacker-Controlled Inputs

- MCP tool arguments (commands, paths, options)
- CLI arguments
- Lab manifest files (`labrunner.yaml`)
- Source project files and paths
- Command output generated in containers
- Export file names and destination parameters

## Residual Risk & Mitigation

A malicious Docker build context or Dockerfile executes through the host Docker daemon during image build. While container isolation restricts execution runtime, Docker is not equivalent to a hardened virtual machine boundary.

For untrusted code analysis, consider:
- Dedicated disposable virtual machines.
- Docker Desktop Enhanced Container Isolation.
- Rootless Docker / gVisor / Kata Containers.
