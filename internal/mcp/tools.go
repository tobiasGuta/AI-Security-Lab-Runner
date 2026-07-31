package mcp

func GetDefinedTools() []Tool {
	return []Tool{
		{
			Name:        "lab_list_projects",
			Description: "List available disposable security lab environments under lab_root.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"include_invalid": {
						Type:        "boolean",
						Description: "If true, includes projects that failed manifest validation.",
					},
				},
			},
		},
		{
			Name:        "lab_start",
			Description: "Start disposable target and runner containers for a given lab project.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"project": {
						Type:        "string",
						Description: "Relative identifier of the lab project to start.",
					},
					"rebuild": {
						Type:        "boolean",
						Description: "Force rebuild of container images.",
					},
				},
				Required: []string{"project"},
			},
		},
		{
			Name:        "lab_exec",
			Description: "Execute a command inside the disposable runner container. NEVER runs on the host.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Active lab session ID.",
					},
					"command": {
						Type:        "string",
						Description: "Command to execute inside runner container.",
					},
					"cwd": {
						Type:        "string",
						Description: "Working directory in runner (/workspace, /scratch, or safe descendant).",
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
			Name:        "lab_read_file",
			Description: "Read a file from /workspace or /scratch inside the runner container.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Active lab session ID.",
					},
					"path": {
						Type:        "string",
						Description: "Container file path (/workspace/... or /scratch/...).",
					},
					"offset": {
						Type:        "integer",
						Description: "Byte offset to start reading from.",
					},
					"maximum_bytes": {
						Type:        "integer",
						Description: "Maximum bytes to read.",
					},
				},
				Required: []string{"session_id", "path"},
			},
		},
		{
			Name:        "lab_write_scratch",
			Description: "Write a script or file strictly under /scratch in the runner container.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Active lab session ID.",
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
			Name:        "lab_status",
			Description: "Show active lab session status.",
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
			Name:        "lab_export_file",
			Description: "Export one regular file from /scratch to host export directory (disabled by default).",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Active lab session ID.",
					},
					"path": {
						Type:        "string",
						Description: "Scratch file path (/scratch/...).",
					},
					"destination_name": {
						Type:        "string",
						Description: "Filename in host export directory.",
					},
				},
				Required: []string{"session_id", "path"},
			},
		},
		{
			Name:        "lab_reset",
			Description: "Destroy and recreate a lab session from manifest.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Active session ID to reset.",
					},
					"rebuild": {
						Type:        "boolean",
						Description: "Force rebuild of images.",
					},
				},
				Required: []string{"session_id"},
			},
		},
		{
			Name:        "lab_stop",
			Description: "Stop a lab session and destroy owned containers/networks.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Session ID to stop.",
					},
					"preserve_scratch": {
						Type:        "boolean",
						Description: "Preserve scratch volume if global policy allows.",
					},
				},
				Required: []string{"session_id"},
			},
		},
		{
			Name:        "lab_get_audit_summary",
			Description: "Get a redacted audit trail summary for a session.",
			InputSchema: ToolSchema{
				Type: "object",
				Properties: map[string]SchemaProperty{
					"session_id": {
						Type:        "string",
						Description: "Session ID to retrieve audit for.",
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
