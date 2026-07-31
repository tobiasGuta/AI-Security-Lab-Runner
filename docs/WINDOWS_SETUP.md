# Windows Setup Guide

## Requirements
- Windows 11 (64-bit)
- Docker Desktop with Linux containers backend enabled
- Go 1.24+ (for building from source)

## Setup Steps

1. Clone the repository:
   ```powershell
   git clone https://github.com/tobiasGuta/AI-Security-Lab-Runner-.git D:\Tools\Lab-Runner
   cd D:\Tools\Lab-Runner
   ```

2. Build the binary & runner image:
   ```powershell
   go build -o lab-runner.exe ./cmd/lab-runner
   docker build -t ai-security-agent-runner:latest -f runner/Dockerfile runner/
   ```

3. Run doctor checks:
   ```powershell
   .\lab-runner.exe doctor
   ```
