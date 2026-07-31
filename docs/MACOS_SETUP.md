# macOS Setup Guide

## Requirements
- macOS 13+ (Apple Silicon or Intel)
- Docker Desktop for Mac
- Go 1.24+

## Setup Steps

```bash
git clone https://github.com/tobiasGuta/AI-Security-Lab-Runner-.git ~/lab-runner
cd ~/lab-runner
go build -o lab-runner ./cmd/lab-runner
docker build -t ai-security-agent-runner:latest -f runner/Dockerfile runner/
./lab-runner doctor
```
