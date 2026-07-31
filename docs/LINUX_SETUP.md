# Linux Setup Guide

## Requirements
- Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+)
- Docker Engine 24.0+ & Docker Compose v2+
- Go 1.24+

## Setup Steps

1. Clone and build:
   ```bash
   git clone https://github.com/tobiasGuta/AI-Security-Lab-Runner-.git /opt/lab-runner
   cd /opt/lab-runner
   go build -o lab-runner ./cmd/lab-runner
   docker build -t ai-security-agent-runner:latest -f runner/Dockerfile runner/
   ```

2. Run health check:
   ```bash
   ./lab-runner doctor
   ```
