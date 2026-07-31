package mcp

func GetDefinedTools() []Tool {
	return []Tool{
		{
			Name:        "sandbox_run",
			Description: "Execute a one-shot command inside a disposable, ephemeral sandbox runner container with automatic cleanup.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"command": {
						Type:        "string",
						Description: "Command to execute inside disposable sandbox (e.g. 'curl -s https://example.com').",
					},
					"cwd": {
						Type:        "string",
						Description: "Working directory in sandbox (/scratch or descendant).",
					},
					"timeout_seconds": {
						Type:        "integer",
						Description: "Execution timeout in seconds.",
					},
				},
				Required: []string{"command"},
			},
		},
		{
			Name:        "sandbox_start",
			Description: "Start a persistent sandbox session with outbound network access and host-gateway translation.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"outbound_network": {
						Type:        "boolean",
						Description: "Enable outbound internet access (optional pointer; true subject to global policy ceiling).",
					},
					"host_access": {
						Type:        "boolean",
						Description: "Enable automatic localhost/127.0.0.1 loopback translation to host gateway (optional pointer; true subject to global policy ceiling).",
					},
					"ttl_minutes": {
						Type:        "integer",
						Description: "Session time-to-live in minutes.",
					},
				},
			},
		},
		{
			Name:        "sandbox_exec",
			Description: "Execute a command inside a persistent sandbox session runner container.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Active sandbox session ID.",
					},
					"command": {
						Type:        "string",
						Description: "Command to execute inside runner container.",
					},
					"cwd": {
						Type:        "string",
						Description: "Working directory inside runner (/scratch or descendant).",
					},
					"timeout_seconds": {
						Type:        "integer",
						Description: "Execution timeout in seconds.",
					},
				},
				Required: []string{"session_id", "command"},
			},
		},
		{
			Name:        "sandbox_http_request",
			Description: "Make a structured HTTP/HTTPS request inside the sandbox using trusted sandbox-http helper. Loopback URLs (localhost/127.0.0.1) translate to host gateway when enabled.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Optional active session ID. If omitted, uses a disposable ephemeral runner.",
					},
					"method": {
						Type:        "string",
						Description: "HTTP method (GET, POST, PUT, DELETE, etc.).",
					},
					"url": {
						Type:        "string",
						Description: "Target URL (e.g. 'https://example.com' or 'http://localhost:3000/api').",
					},
					"headers": {
						Type:        "object",
						Description: "HTTP headers map.",
					},
					"body": {
						Type:        "string",
						Description: "Request body content.",
					},
					"follow_redirects": {
						Type:        "boolean",
						Description: "Follow HTTP redirects.",
					},
					"insecure_tls": {
						Type:        "boolean",
						Description: "Allow insecure TLS certificates.",
					},
					"timeout_seconds": {
						Type:        "integer",
						Description: "Timeout in seconds.",
					},
				},
				Required: []string{"url"},
			},
		},
		{
			Name:        "sandbox_write_file",
			Description: "Write a script or data file strictly under /scratch in the sandbox container.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Active sandbox session ID.",
					},
					"path": {
						Type:        "string",
						Description: "Container file path strictly under /scratch.",
					},
					"content": {
						Type:        "string",
						Description: "File content to write.",
					},
					"encoding": {
						Type:        "string",
						Description: "Content encoding ('utf-8').",
					},
					"overwrite": {
						Type:        "boolean",
						Description: "Allow overwriting existing scratch file.",
					},
				},
				Required: []string{"session_id", "path", "content"},
			},
		},
		{
			Name:        "sandbox_read_file",
			Description: "Read a file strictly under /scratch inside the sandbox container.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Active sandbox session ID.",
					},
					"path": {
						Type:        "string",
						Description: "Container file path under /scratch.",
					},
					"offset": {
						Type:        "integer",
						Description: "Byte offset to start reading from.",
					},
					"maximum_bytes": {
						Type:        "integer",
						Description: "Maximum bytes to read.",
					},
					"binary_encoding": {
						Type:        "string",
						Description: "Binary encoding ('base64' or 'utf-8').",
					},
				},
				Required: []string{"session_id", "path"},
			},
		},
		{
			Name:        "sandbox_export_file",
			Description: "Export a file strictly under /scratch to the configured host export directory.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Active sandbox session ID.",
					},
					"scratch_path": {
						Type:        "string",
						Description: "Container file path strictly under /scratch.",
					},
					"destination_name": {
						Type:        "string",
						Description: "Optional destination filename under export directory.",
					},
				},
				Required: []string{"session_id", "scratch_path"},
			},
		},
		{
			Name:        "sandbox_status",
			Description: "Show active sandbox sessions and status metadata.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Optional session ID to query specific session.",
					},
				},
			},
		},
		{
			Name:        "sandbox_stop",
			Description: "Stop a sandbox session and destroy runner containers and scratch volume.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Session ID to stop.",
					},
				},
				Required: []string{"session_id"},
			},
		},
		{
			Name:        "sandbox_reset",
			Description: "Recreate a persistent sandbox session with the same policy snapshot.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Active session ID to reset.",
					},
				},
				Required: []string{"session_id"},
			},
		},
		{
			Name:        "sandbox_get_audit_summary",
			Description: "Retrieve redacted audit log events for a sandbox session.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Session ID to retrieve audit events for.",
					},
					"limit": {
						Type:        "integer",
						Description: "Maximum event count.",
					},
				},
				Required: []string{"session_id"},
			},
		},
	}
}
