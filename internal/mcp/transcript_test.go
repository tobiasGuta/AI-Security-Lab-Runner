package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/transcript"
)

func TestSandboxGetLogsReturnsCursorAndOptionalOutput(t *testing.T) {
	store, err := transcript.NewStore(t.TempDir(), transcript.Options{
		IncludeCommands: true,
		IncludeOutput:   true,
		RedactSecrets:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(transcript.Event{
		EventID:   "log_first",
		SessionID: "sess_logs",
		Interface: "mcp",
		Tool:      "sandbox_exec",
		Phase:     "completed",
		Command:   "echo hello",
		Stdout:    "hello\n",
	}); err != nil {
		t.Fatal(err)
	}

	server := NewServerWithTranscript(nil, nil, nil, store)
	args := json.RawMessage(`{"session_id":"sess_logs","limit":10,"include_output":false}`)
	result, err := server.executeTool(context.Background(), "sandbox_get_logs", args)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		NextCursor string             `json:"next_cursor"`
		Events     []transcript.Event `json:"events"`
	}
	if err := json.Unmarshal(encoded, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.NextCursor != "log_first" {
		t.Fatalf("unexpected cursor: %q", doc.NextCursor)
	}
	if len(doc.Events) != 1 {
		t.Fatalf("expected one event, got %d", len(doc.Events))
	}
	if doc.Events[0].Stdout != "" {
		t.Fatalf("stdout should be omitted unless include_output=true")
	}
}

func TestTranscriptInputEventDoesNotCaptureHTTPBodyOrHeaders(t *testing.T) {
	args := json.RawMessage(`{
		"session_id":"sess_safe",
		"method":"POST",
		"url":"https://example.com/api",
		"headers":{"Authorization":"Bearer secret"},
		"body":"super-sensitive-body"
	}`)

	sessionID, event := transcriptInputEvent("sandbox_http_request", args)
	if sessionID != "sess_safe" {
		t.Fatalf("unexpected session id: %q", sessionID)
	}
	if event.Method != "POST" || event.URL != "https://example.com/api" {
		t.Fatalf("HTTP metadata not captured correctly: %+v", event)
	}
	if event.Details != nil {
		if _, ok := event.Details["body"]; ok {
			t.Fatalf("HTTP body must not be copied into transcript details")
		}
		if _, ok := event.Details["headers"]; ok {
			t.Fatalf("HTTP headers must not be copied into transcript details")
		}
	}
}

func TestToolsListIncludesSandboxGetLogs(t *testing.T) {
	for _, tool := range GetDefinedTools() {
		if tool.Name == "sandbox_get_logs" {
			return
		}
	}
	t.Fatalf("sandbox_get_logs tool missing from MCP tool list")
}
