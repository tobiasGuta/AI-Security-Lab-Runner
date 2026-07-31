# Threat Model

## Threat Vectors & Mitigation Strategies

| Threat Vector | Mitigation Strategy |
| :--- | :--- |
| Host Command Injection | Fixed Docker argument array execution (`exec.Command("docker", ...)`). No shell invocation on host. |
| Host Filesystem Symlink Escape | Symlink-safe `sandbox-fs` container helper enforcing `/scratch` root. No host workspace mount. |
| Container Privilege Escalation | Non-root `agent` (UID 10001), read-only root filesystem, `cap_drop: ALL`, `no-new-privileges:true`. |
| Docker Socket Abuse | Docker socket prohibited and omitted from compose configurations. |
| Secret Leakage in Logs | Regexp-based secret redaction in JSONL audit logs. |
| Long-Running / Infinite Loops | Container internal GNU `timeout` process termination. |
