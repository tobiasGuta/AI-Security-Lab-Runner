# Network Access & Host Gateway Guide

## Overview

AI Security Lab Runner version 2 provides network access capabilities allowing sandbox commands to interact with:
1. **Public Internet Destinations** (e.g. `https://example.com`, public APIs).
2. **Host-Published Local Applications** (e.g. `http://localhost:3000`, `http://127.0.0.1:8080`).

---

## 1. Public Internet Destinations

Outbound network access is enabled by default in configuration version 2 (`network.outbound_enabled: true`).

Inside the runner container, tools like `curl`, `wget`, `python3`, `node`, `nmap`, and `httpie` can make direct outbound network connections.

---

## 2. Host-Local Application Access & Loopback Translation

Inside a Docker container, `localhost` refers to the container itself.

To reach web services running on your Windows, Linux, or macOS host machine:

### Automatic Loopback Translation (`sandbox_http_request`)
When using `sandbox_http_request`, any request targeting:
- `http://localhost:<port>`
- `http://127.0.0.1:<port>`
- `http://[::1]:<port>`

is automatically routed to `host.docker.internal:<port>` while preserving the original `Host` header (`localhost:<port>`).

### Manual CLI Commands
For raw `sandbox_exec` commands, use `host.docker.internal` directly:
```bash
curl -H "Host: localhost:3000" http://host.docker.internal:3000/
```

---

## 3. Host Gateway Configuration

In generated Compose files, `host-gateway` mapping is added automatically:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

---

## 4. Security Considerations

- Enabling outbound networking permits container commands to reach public networks.
- Always review commands executed by AI agents.
- Docker containers are not a full security boundary for hostile untrusted code; for hostile binaries, use dedicated disposable VMs.
