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

## Session TTL Enforcement

The session expiration timestamp is an execution-admission deadline, not just
informational metadata. Once a session's TTL expires, new `sandbox exec`,
structured HTTP, and scratch file operations are rejected, even if an
execution call was queued before expiry. Commands already admitted before
expiry are allowed to finish; cleanup waits until those execution leases
are released.

During `lab-runner serve` (the stdio MCP server used by AI assistants),
the controller sweeps persisted stale sessions at startup and every 30 seconds.
It uses the same ownership-verified cleanup as `lab-runner cleanup`, and logs
cleanup failures to stderr, never to the MCP protocol stdout. Failed cleanups
remain eligible for later retries. Persisted active-lease counters are not
cleared automatically on restart: without exclusive ownership proof, a second
controller cannot assume an in-flight lease is abandoned. Such records may
need an operator-controlled recovery procedure.

The TTL reaper only operates while the MCP server process is running. There
is no always-on daemon for one-shot CLI calls; use `lab-runner cleanup` to
remove expired sessions when the MCP server isn't running. No automatic
cleanup applies to Docker resources with no persisted session record.
Only one controller instance may own a given state directory at a time.
