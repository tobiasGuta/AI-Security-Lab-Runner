package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditLogAndRedaction(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "audit_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "audit.jsonl")
	logger, err := NewLogger(logFile, true)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	rawCommand := "curl -H 'Authorization: Bearer secret-token-12345' https://example.com"
	evt := Event{
		SessionID:       "sess-123",
		Interface:       "cli",
		ToolOrCommand:   "sandbox_exec",
		RedactedCommand: rawCommand,
	}

	if err := logger.Log(evt); err != nil {
		t.Fatalf("logger.Log failed: %v", err)
	}

	f, err := os.Open(logFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("expected one log entry in audit file")
	}

	var readEvt Event
	if err := json.Unmarshal(scanner.Bytes(), &readEvt); err != nil {
		t.Fatalf("failed to parse logged JSON: %v", err)
	}

	if readEvt.RedactedCommand == rawCommand {
		t.Errorf("expected secret to be redacted in log, but got raw command: %s", readEvt.RedactedCommand)
	}

	// Verify session summary retrieval
	summary, err := logger.GetSummaryForSession("sess-123", 10)
	if err != nil || len(summary) != 1 {
		t.Fatalf("GetSummaryForSession failed: len=%d err=%v", len(summary), err)
	}
}
