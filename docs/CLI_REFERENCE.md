# CLI Reference

## Commands Overview

```powershell
# One-shot command execution with auto-cleanup
lab-runner sandbox run -- curl -s https://example.com

# Start persistent sandbox session
lab-runner sandbox start [--ttl 60]

# Execute command inside active session
lab-runner sandbox exec <session-id> -- id

# Make structured HTTP request (with localhost translation)
lab-runner sandbox request --url http://localhost:3000/api/info --method GET

# Write file to /scratch
lab-runner sandbox write <session-id> /scratch/script.py --file ./script.py

# Read file from /scratch
lab-runner sandbox read <session-id> /scratch/output.txt

# Query sandbox status
lab-runner sandbox status [session-id]

# Stop sandbox session
lab-runner sandbox stop <session-id>

# Reset session
lab-runner sandbox reset <session-id>

# Start stdio MCP server
lab-runner serve

# Infrastructure health check
lab-runner doctor [--json]

# Cleanup stale managed resources
lab-runner cleanup [--dry-run]

# Version information
lab-runner version [--json]
```
