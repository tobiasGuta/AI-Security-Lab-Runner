# Build script for Windows (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "[1/3] Running tests..."
go test ./...

Write-Host "[2/3] Building lab-runner executable..."
go build -o lab-runner.exe ./cmd/lab-runner

Write-Host "[3/3] Building runner Docker image..."
docker build -t ai-security-agent-runner:latest ./runner

Write-Host "Build completed successfully!"
