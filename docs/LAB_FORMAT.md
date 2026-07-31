# Lab Manifest Specification (`labrunner.yaml`)

Every lab directory beneath `lab_root` must contain a `labrunner.yaml` manifest.

## Example `labrunner.yaml`

```yaml
version: 1
name: "hello-web-lab"
description: "Local example target for validating the runner"

workspace: "."

targets:
  - name: "target"
    build:
      context: "."
      dockerfile: "Dockerfile"
    internal_port: 3000
    healthcheck:
      url: "http://target:3000/health"
      timeout_seconds: 30
      interval_seconds: 1
    environment:
      NODE_ENV: "development"

host_access:
  publish: false
  bind_address: "127.0.0.1"

limits:
  target_memory: "512m"
  target_cpus: 0.75
  target_pids: 128
  runner_memory: "1g"
  runner_cpus: 1.0
  runner_pids: 256

runner:
  workspace_mount: "."
  scratch_persistent: false
```

## Security Rules

- Paths must be relative to the lab directory (no `..` or absolute host paths).
- Target names must match `^[a-zA-Z0-9_-]+$` and cannot be `runner`.
- Host bind address is restricted strictly to `127.0.0.1` or `::1`.
