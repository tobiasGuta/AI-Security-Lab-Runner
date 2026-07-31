#!/usr/bin/env bash
set -e

echo "[1/3] Running tests..."
go test ./...

echo "[2/3] Building lab-runner binary..."
go build -o lab-runner ./cmd/lab-runner

echo "[3/3] Building runner Docker image..."
docker build -t ai-security-agent-runner:latest ./runner

echo "Build completed successfully!"
