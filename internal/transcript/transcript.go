package transcript

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/pathsafe"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/validation"
)

var ErrCursorNotFound = errors.New("transcript cursor event not found")

const defaultMaxOutputBytes int64 = 256 * 1024

type Options struct {
	IncludeCommands bool
	IncludeOutput   bool
	RedactSecrets   bool
	MaxOutputBytes  int64
}

type Event struct {
	Timestamp           string                 `json:"timestamp"`
	EventID             string                 `json:"event_id"`
	OperationID         string                 `json:"operation_id,omitempty"`
	SessionID           string                 `json:"session_id"`
	Interface           string                 `json:"interface"`
	Tool                string                 `json:"tool"`
	Phase               string                 `json:"phase"`
	Command             string                 `json:"command,omitempty"`
	Method              string                 `json:"method,omitempty"`
	URL                 string                 `json:"url,omitempty"`
	Path                string                 `json:"path,omitempty"`
	DurationMS          int64                  `json:"duration_ms,omitempty"`
	ExitCode            *int                   `json:"exit_code,omitempty"`
	HTTPStatus          *int                   `json:"http_status,omitempty"`
	TimedOut            bool                   `json:"timed_out,omitempty"`
	OutputTruncated     bool                   `json:"output_truncated,omitempty"`
	TranscriptTruncated bool                   `json:"transcript_truncated,omitempty"`
	Stdout              string                 `json:"stdout,omitempty"`
	Stderr              string                 `json:"stderr,omitempty"`
	Error               string                 `json:"error,omitempty"`
	Details             map[string]interface{} `json:"details,omitempty"`
}

type Store struct {
	mu      sync.Mutex
	dir     string
	options Options
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization:\s*)(bearer|basic)\s+[a-zA-Z0-9._~+/-]+=*`),
	regexp.MustCompile(`(?i)(proxy-authorization:\s*)(bearer|basic)\s+[a-zA-Z0-9._~+/-]+=*`),
	regexp.MustCompile(`(?i)(cookie:\s*)[^\r\n]+`),
	regexp.MustCompile(`(?i)(set-cookie:\s*)[^\r\n]+`),
	regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token|auth_token)\s*[:=]\s*["']?[a-zA-Z0-9._~+/-]+["']?`),
	regexp.MustCompile(`(?i)([?&](password|token|secret|api_key|key)=)[^&\s]+`),
	regexp.MustCompile(`(?i)(https?://)[^:]+:[^@]+@`),
	regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
}

func NewStore(dir string, options Options) (*Store, error) {
	cleanDir, err := pathsafe.CleanHostPath(dir)
	if err != nil {
		return nil, fmt.Errorf("invalid transcript directory: %w", err)
	}
	if options.MaxOutputBytes <= 0 {
		options.MaxOutputBytes = defaultMaxOutputBytes
	}
	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create transcript directory: %w", err)
	}
	return &Store{dir: cleanDir, options: options}, nil
}

func NewEventID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("log_%d", time.Now().UnixNano())
	}
	return "log_" + hex.EncodeToString(b)
}

func (s *Store) Append(event Event) error {
	if err := validation.ValidateIdentifier(event.SessionID); err != nil {
		return fmt.Errorf("invalid transcript session id: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if event.EventID == "" {
		event.EventID = NewEventID()
	}

	s.sanitizeEvent(&event)

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal transcript event: %w", err)
	}
	data = append(data, '\n')

	path := filepath.Join(s.dir, event.SessionID+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open transcript file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to append transcript event: %w", err)
	}
	return nil
}

func (s *Store) ReadSession(sessionID, afterEventID string, limit int) ([]Event, error) {
	if err := validation.ValidateIdentifier(sessionID); err != nil {
		return nil, fmt.Errorf("invalid transcript session id: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, sessionID+".jsonl")
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Event{}, nil
		}
		return nil, fmt.Errorf("failed to open transcript file: %w", err)
	}
	defer f.Close()

	var events []Event
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("failed to decode transcript event: %w", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading transcript: %w", err)
	}

	start := 0
	if afterEventID != "" {
		found := false
		for i := range events {
			if events[i].EventID == afterEventID {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%w: %s", ErrCursorNotFound, afterEventID)
		}
	}

	selected := events[start:]
	if limit > 0 && len(selected) > limit {
		if afterEventID == "" {
			selected = selected[len(selected)-limit:]
		} else {
			selected = selected[:limit]
		}
	}

	result := make([]Event, len(selected))
	copy(result, selected)
	return result, nil
}

func StripOutput(events []Event) []Event {
	result := make([]Event, len(events))
	copy(result, events)
	for i := range result {
		result[i].Stdout = ""
		result[i].Stderr = ""
	}
	return result
}

func (s *Store) sanitizeEvent(event *Event) {
	if !s.options.IncludeCommands {
		event.Command = ""
	}
	if s.options.RedactSecrets {
		event.Command = redact(event.Command)
		event.URL = redact(event.URL)
		event.Error = redact(event.Error)
	}

	if !s.options.IncludeOutput {
		event.Stdout = ""
		event.Stderr = ""
	} else {
		var clipped bool
		event.Stdout, clipped = clip(event.Stdout, s.options.MaxOutputBytes)
		event.TranscriptTruncated = event.TranscriptTruncated || clipped
		event.Stderr, clipped = clip(event.Stderr, s.options.MaxOutputBytes)
		event.TranscriptTruncated = event.TranscriptTruncated || clipped
		if s.options.RedactSecrets {
			event.Stdout = redact(event.Stdout)
			event.Stderr = redact(event.Stderr)
		}
	}

	if event.Details != nil && s.options.RedactSecrets {
		for key, value := range event.Details {
			lower := strings.ToLower(key)
			if lower == "content" || lower == "body" || lower == "payload" || lower == "headers" || lower == "environment" || lower == "base64" {
				event.Details[key] = "[PAYLOAD_REDACTED]"
				continue
			}
			if text, ok := value.(string); ok {
				event.Details[key] = redact(text)
			}
		}
	}
}

func clip(value string, maxBytes int64) (string, bool) {
	if maxBytes <= 0 || int64(len(value)) <= maxBytes {
		return value, false
	}
	return value[:maxBytes], true
}

func redact(input string) string {
	result := input
	for _, pattern := range secretPatterns {
		result = pattern.ReplaceAllString(result, "[REDACTED_SECRET]")
	}
	return result
}
