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

# Preview stale session candidates without deleting anything
lab-runner cleanup --dry-run

# Remove stale sessions and their owned Docker resources, with verification
lab-runner cleanup [--stale] [--config ./config.yaml]

# Version information
lab-runner version [--json]
```

## Stale Cleanup Safety

`lab-runner cleanup` acts only on sessions recorded in the configured state directory:
expired sessions, failed sessions, and sessions with an earlier failed cleanup.
An active session that has not expired is left untouched. A session with
a recorded active execution lease is not selected.

The optional `--stale` flag is retained for compatibility; stale-only cleanup
is the default. `--dry-run` lists candidates but does not remove Docker
resources or change session state.

Each deletion uses the same ownership-checked, resource-absence-verified
path as `sandbox stop`. A failed cleanup is reported per session, keeps
retryable state, and makes the command exit nonzero. Success is reported only
after the runner, network, scratch volume, and session state are confirmed
removed.

Cleanup does **not** sweep arbitrary Docker containers, remove active
unexpired sessions, or delete orphaned resources that have no persisted
session record. Review those separately instead of deleting by label alone.
Do not run separate controller instances against the same state directory
concurrently.
