# Security Model & Invariants

## Core Invariants

1. **No Host Command Execution**: Agent commands are executed ONLY inside the isolated Docker runner container.
2. **Container Internal Timeout Enforcement**: Container executions are wrapped with GNU `timeout --signal=TERM --kill-after=2s` inside the container.
3. **No Host Filesystem Mounts**: Host `/workspace` mount removed in version 2. `/scratch` volume is the only writable directory.
4. **No Docker Socket**: `/var/run/docker.sock` is never exposed.
5. **No Privileged Mode**: Containers run with dropped Linux capabilities (`cap_drop: ALL`) and `no-new-privileges:true`.
6. **Non-Root Execution**: User `agent` (UID 10001).
7. **Symlink Containment**: `sandbox-fs` helper enforces `/scratch` root boundary for reads, writes, stats, and hashes.
8. **Redacted Audit Log**: Passwords, tokens, bearer headers, cookies, API keys redacted automatically.
