package transcript

import (
	"strings"
	"testing"
)

func TestStoreAppendReadRedactsAndClips(t *testing.T) {
	store, err := NewStore(t.TempDir(), Options{
		IncludeCommands: true,
		IncludeOutput:   true,
		RedactSecrets:   true,
		MaxOutputBytes:  64,
	})
	if err != nil {
		t.Fatal(err)
	}

	exit := 0
	event := Event{
		SessionID: "sess_test",
		Interface: "mcp",
		Tool:      "sandbox_exec",
		Phase:     "completed",
		Command:   "curl -H 'Authorization: Bearer supersecret' https://example.com?token=abc123",
		ExitCode:  &exit,
		Stdout:    "token=abc123 " + strings.Repeat("x", 100),
	}
	if err := store.Append(event); err != nil {
		t.Fatal(err)
	}

	events, err := store.ReadSession("sess_test", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	got := events[0]
	if strings.Contains(got.Command, "supersecret") || strings.Contains(got.Command, "abc123") {
		t.Fatalf("command was not redacted: %q", got.Command)
	}
	if strings.Contains(got.Stdout, "abc123") {
		t.Fatalf("stdout was not redacted: %q", got.Stdout)
	}
	if !got.TranscriptTruncated {
		t.Fatalf("expected transcript output truncation")
	}
}

func TestStoreRedactsStructuredCredentialsWithoutOverRedactingContext(t *testing.T) {
	store, err := NewStore(t.TempDir(), Options{
		IncludeOutput:  true,
		RedactSecrets:  true,
		MaxOutputBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}

	stdout := `{"access_token":"access-secret","refresh_token":"refresh-secret","id_token":"id-secret","password":"password-secret","scope":"openid profile","object_id":"obj_123","code":"authorization-code-for-analysis"}`
	if err := store.Append(Event{
		SessionID: "sess_structured",
		Interface: "mcp",
		Tool:      "sandbox_exec",
		Phase:     "completed",
		Stdout:    stdout,
	}); err != nil {
		t.Fatal(err)
	}

	events, err := store.ReadSession("sess_structured", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	got := events[0].Stdout
	for _, secret := range []string{"access-secret", "refresh-secret", "id-secret", "password-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("structured credential leaked into transcript: %q", got)
		}
	}
	for _, useful := range []string{"access_token", "refresh_token", "id_token", "password", "openid profile", "obj_123", "authorization-code-for-analysis"} {
		if !strings.Contains(got, useful) {
			t.Fatalf("useful hunting context was over-redacted (%q missing): %q", useful, got)
		}
	}
	if strings.Count(got, "[REDACTED_SECRET]") < 4 {
		t.Fatalf("expected structured credentials to be visibly redacted: %q", got)
	}
}

func TestStoreRedactsTruncatedPrivateKeyBeforeClipping(t *testing.T) {
	store, err := NewStore(t.TempDir(), Options{
		IncludeOutput:  true,
		RedactSecrets:  true,
		MaxOutputBytes: 96,
	})
	if err != nil {
		t.Fatal(err)
	}

	stdout := "before-key\n-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("A", 256)
	if err := store.Append(Event{
		SessionID: "sess_private_key",
		Interface: "mcp",
		Tool:      "sandbox_exec",
		Phase:     "completed",
		Stdout:    stdout,
	}); err != nil {
		t.Fatal(err)
	}

	events, err := store.ReadSession("sess_private_key", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	got := events[0]
	if strings.Contains(got.Stdout, "BEGIN PRIVATE KEY") || strings.Contains(got.Stdout, strings.Repeat("A", 16)) {
		t.Fatalf("truncated private key leaked into transcript: %q", got.Stdout)
	}
	if !strings.Contains(got.Stdout, "before-key") || !strings.Contains(got.Stdout, "[REDACTED_SECRET]") {
		t.Fatalf("expected safe context plus redaction marker, got: %q", got.Stdout)
	}
	if !got.TranscriptTruncated {
		t.Fatalf("expected transcript truncation metadata for oversized original output")
	}
}

func TestReadSessionCursor(t *testing.T) {
	store, err := NewStore(t.TempDir(), Options{IncludeCommands: true})
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"log_a", "log_b", "log_c"} {
		if err := store.Append(Event{
			EventID:   id,
			SessionID: "sess_cursor",
			Interface: "mcp",
			Tool:      "sandbox_exec",
			Phase:     "completed",
		}); err != nil {
			t.Fatal(err)
		}
	}

	events, err := store.ReadSession("sess_cursor", "log_a", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].EventID != "log_b" || events[1].EventID != "log_c" {
		t.Fatalf("unexpected cursor result: %+v", events)
	}

	tail, err := store.ReadSession("sess_cursor", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 2 || tail[0].EventID != "log_b" || tail[1].EventID != "log_c" {
		t.Fatalf("unexpected tail result: %+v", tail)
	}
}

func TestStripOutput(t *testing.T) {
	events := []Event{{Stdout: "secret", Stderr: "error"}}
	stripped := StripOutput(events)
	if stripped[0].Stdout != "" || stripped[0].Stderr != "" {
		t.Fatalf("expected output to be stripped")
	}
	if events[0].Stdout != "secret" {
		t.Fatalf("StripOutput mutated original slice")
	}
}
