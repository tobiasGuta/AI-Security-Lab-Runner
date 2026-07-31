package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/pathsafe"
)

var (
	ErrAuditFailed = errors.New("audit log write failed")

	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(authorization:\s*)(bearer|basic)\s+[a-zA-Z0-9._~+/-]+=*`),
		regexp.MustCompile(`(?i)(cookie:\s*)[^\r\n]+`),
		regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token|auth_token)\s*[:=]\s*["']?[a-zA-Z0-9._~+/-]+["']?`),
		regexp.MustCompile(`-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`),
	}
)

type Event struct {
	Timestamp       string                 `json:"timestamp"`
	EventID         string                 `json:"event_id"`
	SessionID       string                 `json:"session_id,omitempty"`
	Interface       string                 `json:"interface"` // "mcp" or "cli"
	ToolOrCommand   string                 `json:"tool_or_command"`
	DurationMS      int64                  `json:"duration_ms,omitempty"`
	ExitCode        *int                   `json:"exit_code,omitempty"`
	TimedOut        bool                   `json:"timed_out,omitempty"`
	OutputTruncated bool                   `json:"output_truncated,omitempty"`
	RedactedCommand string                 `json:"redacted_command,omitempty"`
	ErrorCategory   string                 `json:"error_category,omitempty"`
	Resources       []string               `json:"resources,omitempty"`
	Details         map[string]interface{} `json:"details,omitempty"`
}

type Logger struct {
	mu            sync.Mutex
	logFilePath   string
	redactSecrets bool
}

func NewLogger(logFilePath string, redactSecrets bool) (*Logger, error) {
	if logFilePath == "" {
		return nil, fmt.Errorf("audit log file path cannot be empty")
	}

	cleanPath, err := pathsafe.CleanHostPath(logFilePath)
	if err != nil {
		return nil, fmt.Errorf("invalid audit log path: %w", err)
	}

	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	return &Logger{
		logFilePath:   cleanPath,
		redactSecrets: redactSecrets,
	}, nil
}

func GenerateEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("evt_%s", hex.EncodeToString(b))
}

func (l *Logger) Log(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if event.EventID == "" {
		event.EventID = GenerateEventID()
	}

	if l.redactSecrets {
		event.RedactedCommand = l.Redact(event.RedactedCommand)
		if event.Details != nil {
			for k, v := range event.Details {
				if strVal, ok := v.(string); ok {
					event.Details[k] = l.Redact(strVal)
				}
			}
		}
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}
	data = append(data, '\n')

	f, err := os.OpenFile(l.logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("%w: failed to open audit log: %v", ErrAuditFailed, err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("%w: failed to write audit log: %v", ErrAuditFailed, err)
	}

	return nil
}

func (l *Logger) GetSummaryForSession(sessionID string, limit int) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.logFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Event{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var events []Event
	decoder := json.NewDecoder(f)
	for decoder.More() {
		var evt Event
		if err := decoder.Decode(&evt); err == nil {
			if evt.SessionID == sessionID {
				events = append(events, evt)
			}
		}
	}

	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}

	return events, nil
}

func (l *Logger) Redact(input string) string {
	if input == "" {
		return ""
	}
	res := input
	for _, pattern := range secretPatterns {
		res = pattern.ReplaceAllString(res, "[REDACTED_SECRET]")
	}
	return res
}
