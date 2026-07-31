# Host Configuration Guide

`lab-runner` uses YAML for host configuration settings.

## Configuration Schema (v1)

```yaml
version: 1

lab_root: "D:\\Labs"
state_dir: "C:\\Users\\ExampleUser\\.ai-security-lab-runner"
audit_log: "C:\\Users\\ExampleUser\\.ai-security-lab-runner\\audit.jsonl"
export_dir: "D:\\Labs\\Exports"

runner:
  image: "ai-security-agent-runner:latest"
  dockerfile: "D:\\Tools\\Lab-Runner\\runner\\Dockerfile"
  pull_policy: "never"

limits:
  default_timeout_seconds: 30
  maximum_timeout_seconds: 120
  shutdown_grace_seconds: 10
  maximum_output_bytes: 1048576
  maximum_write_bytes: 1048576
  maximum_read_bytes: 2097152
  maximum_export_bytes: 5242880
  session_ttl_minutes: 120
  maximum_sessions: 4
  maximum_parallel_exec_per_session: 1
  maximum_parallel_global_exec: 4

security:
  allow_export: false
  allow_host_port_publish: false
  preserve_scratch_on_stop: false
  remove_session_on_start_failure: true
  require_internal_network: true
  allow_internet_egress: false
  command_policy: "container-only"

logging:
  level: "info"
  include_commands: true
  include_command_output: false
  redact_environment_values: true
  redact_known_secret_patterns: true
```

## Precedence Order

1. Built-in secure defaults.
2. YAML configuration file.
3. Environment variables (`LAB_RUNNER_...`).
4. Explicit CLI flags.
