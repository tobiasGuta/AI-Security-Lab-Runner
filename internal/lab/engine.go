package lab

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/audit"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/docker"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/pathsafe"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/security"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/session"
)

var (
	ErrExportDisabled     = errors.New("file export is disabled by security policy")
	ErrInvalidScratchPath = errors.New("file operation is restricted strictly to /scratch descendants")
	ErrInvalidHTTPMethod  = errors.New("invalid or unsupported HTTP method")
	ErrInvalidHeaderName  = errors.New("invalid HTTP header name")
	ErrPolicyDenied       = errors.New("POLICY_DENIED: requested feature exceeds global configuration policy ceiling")
)

type Engine struct {
	cfg          *config.Config
	dockerClient docker.Client
	sessMgr      *session.Manager
	auditLogger  *audit.Logger
}

func NewEngine(cfg *config.Config, dockerClient docker.Client, auditLogger *audit.Logger) (*Engine, error) {
	mgr, err := session.NewManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize session manager: %w", err)
	}

	return &Engine{
		cfg:          cfg,
		dockerClient: dockerClient,
		sessMgr:      mgr,
		auditLogger:  auditLogger,
	}, nil
}

type RunResult struct {
	SessionID       string                 `json:"session_id"`
	Ephemeral       bool                   `json:"ephemeral"`
	ExitCode        int                    `json:"exit_code"`
	TimedOut        bool                   `json:"timed_out"`
	DurationMS      int64                  `json:"duration_ms"`
	Stdout          string                 `json:"stdout"`
	Stderr          string                 `json:"stderr"`
	StdoutTruncated bool                   `json:"stdout_truncated"`
	StderrTruncated bool                   `json:"stderr_truncated"`
	Cleanup         session.CleanupSummary `json:"cleanup"`
}

func (e *Engine) Run(ctx context.Context, command, cwd string, timeoutSec int, env map[string]string) (*RunResult, error) {
	timeoutSec = e.clampTimeout(timeoutSec)

	sess, err := e.sessMgr.CreateSession(session.ModeEphemeral, 15, e.cfg.Network.OutboundEnabled, e.cfg.Network.HostGatewayEnabled)
	if err != nil {
		return nil, fmt.Errorf("failed to create ephemeral session: %w", err)
	}

	res := &RunResult{
		SessionID: sess.ID,
		Ephemeral: true,
	}

	defer func() {
		summary, _ := e.cleanupSession(context.Background(), sess.ID)
		res.Cleanup = summary
	}()

	_ = e.sessMgr.Transition(sess.ID, session.StateCreated, session.StateStarting)

	composeContent, err := docker.GenerateComposeYAML(sess.ID, sess.OutboundEnabled, sess.HostGatewayEnabled, e.cfg)
	if err != nil {
		e.rollbackStartup(ctx, sess.ID)
		return res, fmt.Errorf("failed to generate compose configuration: %w", err)
	}

	if err := os.WriteFile(sess.ComposeFilePath, []byte(composeContent), 0600); err != nil {
		e.rollbackStartup(ctx, sess.ID)
		return res, fmt.Errorf("failed to write compose file: %w", err)
	}

	snap, err := e.dockerClient.ComposeUp(ctx, sess.ComposeProject, sess.ComposeFilePath)
	if err != nil {
		e.rollbackStartup(ctx, sess.ID)
		return res, fmt.Errorf("failed to bring up runner container: %w", err)
	}

	_ = e.sessMgr.UpdateSessionState(sess.ID, func(s *session.Session) {
		s.RunnerContainerID = snap.RunnerContainerID
		s.NetworkID = snap.NetworkID
		s.VolumeName = snap.ScratchVolumeName
		s.Status = session.StateReady
	})

	if cwd == "" {
		cwd = "/scratch"
	}
	cleanCwd, err := pathsafe.ValidateContainerPathUnderAllowed(cwd, []string{"/scratch", "/tmp"})
	if err != nil {
		return res, fmt.Errorf("invalid working directory: %w", err)
	}

	start := time.Now()
	exitCode, stdout, stderr, timedOut, truncated, err := e.dockerClient.ExecInRunner(
		ctx,
		sess.ComposeProject,
		sess.ComposeFilePath,
		cleanCwd,
		command,
		env,
		time.Duration(timeoutSec)*time.Second,
		e.cfg.Limits.MaximumOutputBytes,
	)
	res.DurationMS = time.Since(start).Milliseconds()

	res.ExitCode = exitCode
	res.Stdout = stdout
	res.Stderr = stderr
	res.TimedOut = timedOut
	res.StdoutTruncated = truncated
	res.StderrTruncated = truncated

	if e.auditLogger != nil {
		_ = e.auditLogger.Log(audit.Event{
			SessionID:       sess.ID,
			Interface:       "engine",
			ToolOrCommand:   "sandbox_run",
			AuditMode:       audit.AuditCommand,
			DurationMS:      res.DurationMS,
			ExitCode:        &exitCode,
			TimedOut:        timedOut,
			OutputTruncated: truncated,
			RedactedCommand: command,
		})
	}

	if err != nil {
		return res, fmt.Errorf("execution failed: %w", err)
	}

	return res, nil
}

type StartResult struct {
	SessionID     string                 `json:"session_id"`
	Status        string                 `json:"status"`
	CreatedAt     time.Time              `json:"created_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
	Network       config.NetworkConfig   `json:"network"`
	HostGateway   string                 `json:"host_gateway"`
	PolicySummary security.PolicySummary `json:"policy_summary"`
}

func (e *Engine) StartSession(ctx context.Context, reqOutbound, reqHostAccess *bool, ttlMinutes int) (*StartResult, error) {
	effectiveOutbound, err := e.resolveNetworkPolicy(reqOutbound, e.cfg.Network.OutboundEnabled, "outbound_network")
	if err != nil {
		return nil, err
	}
	effectiveHostAccess, err := e.resolveNetworkPolicy(reqHostAccess, e.cfg.Network.HostGatewayEnabled, "host_gateway_translation")
	if err != nil {
		return nil, err
	}

	sess, err := e.sessMgr.CreateSession(session.ModePersistent, ttlMinutes, effectiveOutbound, effectiveHostAccess)
	if err != nil {
		return nil, err
	}

	_ = e.sessMgr.Transition(sess.ID, session.StateCreated, session.StateStarting)

	composeContent, err := docker.GenerateComposeYAML(sess.ID, sess.OutboundEnabled, sess.HostGatewayEnabled, e.cfg)
	if err != nil {
		e.rollbackStartup(ctx, sess.ID)
		return nil, fmt.Errorf("failed to generate compose yaml: %w", err)
	}

	if err := os.WriteFile(sess.ComposeFilePath, []byte(composeContent), 0600); err != nil {
		e.rollbackStartup(ctx, sess.ID)
		return nil, fmt.Errorf("failed to write compose file: %w", err)
	}

	snap, err := e.dockerClient.ComposeUp(ctx, sess.ComposeProject, sess.ComposeFilePath)
	if err != nil {
		e.rollbackStartup(ctx, sess.ID)
		return nil, fmt.Errorf("docker compose up failed: %w", err)
	}

	_ = e.sessMgr.UpdateSessionState(sess.ID, func(s *session.Session) {
		s.RunnerContainerID = snap.RunnerContainerID
		s.NetworkID = snap.NetworkID
		s.VolumeName = snap.ScratchVolumeName
		s.Status = session.StateReady
	})

	if e.auditLogger != nil {
		_ = e.auditLogger.Log(audit.Event{
			SessionID:     sess.ID,
			Interface:     "engine",
			ToolOrCommand: "sandbox_start",
			AuditMode:     audit.AuditMetadataOnly,
			Resources:     []string{sess.ComposeProject},
		})
	}

	netPolicy := e.cfg.Network
	netPolicy.OutboundEnabled = sess.OutboundEnabled
	netPolicy.HostGatewayEnabled = sess.HostGatewayEnabled

	return &StartResult{
		SessionID:     sess.ID,
		Status:        string(session.StateReady),
		CreatedAt:     sess.CreatedAt,
		ExpiresAt:     sess.ExpiresAt,
		Network:       netPolicy,
		HostGateway:   e.cfg.Network.HostGatewayName,
		PolicySummary: security.GetPolicySummary(e.cfg),
	}, nil
}

type ExecResult struct {
	SessionID       string `json:"session_id"`
	ExitCode        int    `json:"exit_code"`
	TimedOut        bool   `json:"timed_out"`
	DurationMS      int64  `json:"duration_ms"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

func (e *Engine) Exec(ctx context.Context, sessID, command, cwd string, timeoutSec int, env map[string]string) (*ExecResult, error) {
	timeoutSec = e.clampTimeout(timeoutSec)

	if cwd == "" {
		cwd = "/scratch"
	}
	cleanCwd, err := pathsafe.ValidateContainerPathUnderAllowed(cwd, []string{"/scratch", "/tmp"})
	if err != nil {
		return nil, fmt.Errorf("invalid execution working directory: %w", err)
	}

	releaseLease, err := e.sessMgr.AcquireExecLease(ctx, sessID)
	if err != nil {
		return nil, fmt.Errorf("execution lease denied: %w", err)
	}
	defer releaseLease()

	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(timeoutSec) * time.Second

	start := time.Now()
	exitCode, stdout, stderr, timedOut, truncated, err := e.dockerClient.ExecInRunner(
		ctx,
		sess.ComposeProject,
		sess.ComposeFilePath,
		cleanCwd,
		command,
		env,
		timeout,
		e.cfg.Limits.MaximumOutputBytes,
	)
	duration := time.Since(start).Milliseconds()

	if e.auditLogger != nil {
		_ = e.auditLogger.Log(audit.Event{
			SessionID:       sessID,
			Interface:       "engine",
			ToolOrCommand:   "sandbox_exec",
			AuditMode:       audit.AuditCommand,
			DurationMS:      duration,
			ExitCode:        &exitCode,
			TimedOut:        timedOut,
			OutputTruncated: truncated,
			RedactedCommand: command,
		})
	}

	if err != nil {
		return nil, fmt.Errorf("container command execution failed: %w", err)
	}

	return &ExecResult{
		SessionID:       sessID,
		ExitCode:        exitCode,
		TimedOut:        timedOut,
		DurationMS:      duration,
		Stdout:          stdout,
		Stderr:          stderr,
		StdoutTruncated: truncated,
		StderrTruncated: truncated,
	}, nil
}

// execInternalArgv executes raw argv + stdin without command string audit logging or base64 shell expansion.
func (e *Engine) execInternalArgv(ctx context.Context, sessID string, argv []string, stdin []byte, timeoutSec int) (*ExecResult, error) {
	timeoutSec = e.clampTimeout(timeoutSec)

	var sess *session.Session
	var err error
	var releaseLease func()
	actualSessID := sessID

	if sessID != "" {
		releaseLease, err = e.sessMgr.AcquireExecLease(ctx, sessID)
		if err != nil {
			return nil, fmt.Errorf("internal execution lease denied: %w", err)
		}
		defer releaseLease()

		sess, err = e.sessMgr.GetSession(sessID)
		if err != nil {
			return nil, err
		}
	}

	timeout := time.Duration(timeoutSec) * time.Second

	start := time.Now()
	var exitCode int
	var stdout, stderr string
	var timedOut, truncated bool

	if sess != nil {
		exitCode, stdout, stderr, timedOut, truncated, err = e.dockerClient.ExecArgvWithInputInRunner(
			ctx,
			sess.ComposeProject,
			sess.ComposeFilePath,
			"/scratch",
			argv,
			stdin,
			nil,
			timeout,
			e.cfg.Limits.MaximumOutputBytes,
		)
	} else {
		// Ephemeral execution path with startup rollback
		ephSess, createErr := e.sessMgr.CreateSession(session.ModeEphemeral, 15, e.cfg.Network.OutboundEnabled, e.cfg.Network.HostGatewayEnabled)
		if createErr != nil {
			return nil, fmt.Errorf("failed to create ephemeral session: %w", createErr)
		}
		actualSessID = ephSess.ID
		defer func() {
			_, _ = e.cleanupSession(context.Background(), ephSess.ID)
		}()

		composeContent, genErr := docker.GenerateComposeYAML(ephSess.ID, ephSess.OutboundEnabled, ephSess.HostGatewayEnabled, e.cfg)
		if genErr != nil {
			e.rollbackStartup(ctx, ephSess.ID)
			return nil, fmt.Errorf("ephemeral compose YAML failed: %w", genErr)
		}

		if writeErr := os.WriteFile(ephSess.ComposeFilePath, []byte(composeContent), 0600); writeErr != nil {
			e.rollbackStartup(ctx, ephSess.ID)
			return nil, fmt.Errorf("ephemeral write compose file failed: %w", writeErr)
		}

		snap, upErr := e.dockerClient.ComposeUp(ctx, ephSess.ComposeProject, ephSess.ComposeFilePath)
		if upErr != nil {
			e.rollbackStartup(ctx, ephSess.ID)
			return nil, fmt.Errorf("ephemeral compose up failed: %w", upErr)
		}
		_ = e.sessMgr.UpdateSessionState(ephSess.ID, func(s *session.Session) {
			s.RunnerContainerID = snap.RunnerContainerID
			s.NetworkID = snap.NetworkID
			s.VolumeName = snap.ScratchVolumeName
			s.Status = session.StateReady
		})

		exitCode, stdout, stderr, timedOut, truncated, err = e.dockerClient.ExecArgvWithInputInRunner(
			ctx,
			ephSess.ComposeProject,
			ephSess.ComposeFilePath,
			"/scratch",
			argv,
			stdin,
			nil,
			timeout,
			e.cfg.Limits.MaximumOutputBytes,
		)
	}

	duration := time.Since(start).Milliseconds()

	if err != nil {
		return nil, fmt.Errorf("internal argv execution failed: %w", err)
	}

	return &ExecResult{
		SessionID:       actualSessID,
		ExitCode:        exitCode,
		TimedOut:        timedOut,
		DurationMS:      duration,
		Stdout:          stdout,
		Stderr:          stderr,
		StdoutTruncated: truncated,
		StderrTruncated: truncated,
	}, nil
}

type HTTPRequestOptions struct {
	SessionID       string            `json:"session_id,omitempty"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	FollowRedirects bool              `json:"follow_redirects"`
	InsecureTLS     bool              `json:"insecure_tls"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	SaveCookiesPath string            `json:"save_cookies_path,omitempty"`
	LoadCookiesPath string            `json:"load_cookies_path,omitempty"`
}

type HTTPRequestResult struct {
	RequestedURL           string              `json:"requested_url"`
	EffectiveURL           string              `json:"effective_url"`
	StatusCode             int                 `json:"status_code"`
	Headers                map[string][]string `json:"headers"`
	Body                   string              `json:"body"`
	BodyBase64             bool                `json:"body_base64"`
	DurationMS             int64               `json:"duration_ms"`
	RedirectChain          []string            `json:"redirect_chain"`
	ExitCode               int                 `json:"curl_exit_code"` // Kept JSON tag for backward compatibility
	ErrorCategory          string              `json:"error_category,omitempty"`
	HostGatewayTranslation bool                `json:"host_gateway_translation"`
	ConnectionHost         string              `json:"connection_host"`
	Truncated              bool                `json:"truncated"`
}

func (e *Engine) HTTPRequest(ctx context.Context, opts HTTPRequestOptions) (*HTTPRequestResult, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("URL cannot be empty")
	}

	parsedURL, err := url.Parse(opts.URL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, fmt.Errorf("invalid URL scheme (must be http or https): %s", opts.URL)
	}

	opts.TimeoutSeconds = e.clampTimeout(opts.TimeoutSeconds)

	for k, v := range opts.Headers {
		if strings.ContainsAny(k, "\r\n:") {
			return nil, fmt.Errorf("%w: invalid header name '%s'", ErrInvalidHeaderName, k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%w: CRLF in header value for key '%s'", ErrInvalidHeaderName, k)
		}
	}

	hostGatewayEnabled := e.cfg.Network.HostGatewayEnabled
	if opts.SessionID != "" {
		if sess, err := e.sessMgr.GetSession(opts.SessionID); err == nil {
			hostGatewayEnabled = sess.HostGatewayEnabled
		}
	}

	specObj := map[string]interface{}{
		"method":               opts.Method,
		"url":                  opts.URL,
		"headers":              opts.Headers,
		"body":                 opts.Body,
		"follow_redirects":     opts.FollowRedirects,
		"insecure_tls":         opts.InsecureTLS,
		"timeout_seconds":      opts.TimeoutSeconds,
		"save_cookies_path":    opts.SaveCookiesPath,
		"load_cookies_path":    opts.LoadCookiesPath,
		"host_gateway_name":    e.cfg.Network.HostGatewayName,
		"host_gateway_enabled": hostGatewayEnabled,
		"max_response_bytes":   e.cfg.Limits.MaximumReadBytes,
	}

	specData, err := json.Marshal(specObj)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HTTP request specification: %w", err)
	}

	argv := []string{"/usr/local/bin/sandbox-http"}
	execRes, err := e.execInternalArgv(ctx, opts.SessionID, argv, specData, opts.TimeoutSeconds)
	if err != nil {
		return nil, err
	}

	var resDoc HTTPRequestResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(execRes.Stdout)), &resDoc); err != nil {
		return nil, fmt.Errorf("failed to parse sandbox-http JSON output: %w (raw: %s)", err, execRes.Stdout)
	}

	if e.auditLogger != nil {
		sanitizedURL := opts.URL
		if u, err := url.Parse(opts.URL); err == nil && u.User != nil {
			u.User = url.UserPassword("[REDACTED]", "[REDACTED]")
			sanitizedURL = u.String()
		}

		bodyHash := sha256.Sum256([]byte(opts.Body))

		_ = e.auditLogger.Log(audit.Event{
			SessionID:     opts.SessionID,
			Interface:     "engine",
			ToolOrCommand: "sandbox_http_request",
			AuditMode:     audit.AuditMetadataOnly,
			DurationMS:    execRes.DurationMS,
			ExitCode:      &resDoc.ExitCode,
			Details: map[string]interface{}{
				"method":      opts.Method,
				"url":         sanitizedURL,
				"status":      resDoc.StatusCode,
				"body_bytes":  len(opts.Body),
				"body_sha256": hex.EncodeToString(bodyHash[:]),
			},
		})
	}

	return &resDoc, nil
}

type ReadResult struct {
	SessionID string `json:"session_id"`
	Path      string `json:"path"`
	Content   string `json:"content"`
	Encoding  string `json:"encoding"`
	Truncated bool   `json:"truncated"`
}

func (e *Engine) ReadFile(ctx context.Context, sessID, containerPath string, offset int64, maxBytes int64, binaryEncoding string) (*ReadResult, error) {
	cleanPath, err := pathsafe.ValidateContainerPathUnderAllowed(containerPath, []string{"/scratch"})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidScratchPath, err)
	}

	if offset < 0 {
		return nil, fmt.Errorf("invalid offset %d (must be >= 0)", offset)
	}

	if maxBytes <= 0 || maxBytes > e.cfg.Limits.MaximumReadBytes {
		maxBytes = e.cfg.Limits.MaximumReadBytes
	}

	if binaryEncoding == "" {
		binaryEncoding = "utf-8"
	}
	if binaryEncoding != "utf-8" && binaryEncoding != "base64" {
		return nil, fmt.Errorf("unsupported binary_encoding '%s' (must be 'utf-8' or 'base64')", binaryEncoding)
	}

	statArgv := []string{"/usr/local/bin/sandbox-fs", "stat", cleanPath}
	statRes, err := e.execInternalArgv(ctx, sessID, statArgv, nil, 10)
	if err != nil || statRes.ExitCode != 0 {
		return nil, fmt.Errorf("sandbox-fs stat failed for '%s': %s", cleanPath, statRes.Stderr)
	}

	var statObj map[string]interface{}
	_ = json.Unmarshal([]byte(strings.TrimSpace(statRes.Stdout)), &statObj)
	totalFileSize := int64(0)
	if sizeVal, ok := statObj["size"].(float64); ok {
		totalFileSize = int64(sizeVal)
	}

	readArgv := []string{"/usr/local/bin/sandbox-fs", "read", cleanPath, strconv.FormatInt(offset, 10), strconv.FormatInt(maxBytes, 10)}
	res, err := e.execInternalArgv(ctx, sessID, readArgv, nil, 15)
	if err != nil || res.ExitCode != 0 {
		return nil, fmt.Errorf("sandbox-fs read failed for '%s': exit code %d, stderr: %s", cleanPath, res.ExitCode, res.Stderr)
	}

	content := res.Stdout
	if binaryEncoding == "base64" {
		content = base64.StdEncoding.EncodeToString([]byte(res.Stdout))
	}

	isTruncated := (offset + int64(len(res.Stdout))) < totalFileSize

	if e.auditLogger != nil {
		_ = e.auditLogger.Log(audit.Event{
			SessionID:     sessID,
			Interface:     "engine",
			ToolOrCommand: "sandbox_read_file",
			AuditMode:     audit.AuditMetadataOnly,
			Details: map[string]interface{}{
				"path":       cleanPath,
				"bytes_read": len(res.Stdout),
				"offset":     offset,
			},
		})
	}

	return &ReadResult{
		SessionID: sessID,
		Path:      cleanPath,
		Content:   content,
		Encoding:  binaryEncoding,
		Truncated: isTruncated,
	}, nil
}

type WriteResult struct {
	SessionID      string `json:"session_id"`
	NormalizedPath string `json:"normalized_path"`
	BytesWritten   int64  `json:"bytes_written"`
}

func (e *Engine) WriteFile(ctx context.Context, sessID, scratchPath, content, encoding string, overwrite bool) (*WriteResult, error) {
	cleanPath, err := pathsafe.ValidateContainerPathUnderAllowed(scratchPath, []string{"/scratch"})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidScratchPath, err)
	}

	if int64(len(content)) > e.cfg.Limits.MaximumWriteBytes {
		return nil, fmt.Errorf("content size %d exceeds write limit %d", len(content), e.cfg.Limits.MaximumWriteBytes)
	}

	overwriteStr := "false"
	if overwrite {
		overwriteStr = "true"
	}

	argv := []string{"/usr/local/bin/sandbox-fs", "write", cleanPath, overwriteStr}
	res, err := e.execInternalArgv(ctx, sessID, argv, []byte(content), 15)
	if err != nil || (res != nil && res.ExitCode != 0) {
		if res != nil && res.ExitCode == 17 {
			return nil, fmt.Errorf("file '%s' already exists and overwrite is false", cleanPath)
		}
		stderrMsg := ""
		if res != nil {
			stderrMsg = res.Stderr
		}
		return nil, fmt.Errorf("sandbox-fs write failed for '%s': %v (stderr: %s)", cleanPath, err, stderrMsg)
	}

	contentHash := sha256.Sum256([]byte(content))

	if e.auditLogger != nil {
		_ = e.auditLogger.Log(audit.Event{
			SessionID:     sessID,
			Interface:     "engine",
			ToolOrCommand: "sandbox_write_file",
			AuditMode:     audit.AuditMetadataOnly,
			Details: map[string]interface{}{
				"path":           cleanPath,
				"bytes_written":  len(content),
				"content_sha256": hex.EncodeToString(contentHash[:]),
				"overwrite":      overwrite,
			},
		})
	}

	return &WriteResult{
		SessionID:      sessID,
		NormalizedPath: cleanPath,
		BytesWritten:   int64(len(content)),
	}, nil
}

type PublicStatus struct {
	SessionID       string                `json:"session_id"`
	Mode            string                `json:"mode"`
	Status          string                `json:"status"`
	CreatedAt       time.Time             `json:"created_at"`
	ExpiresAt       time.Time             `json:"expires_at"`
	ActiveExecCount int                   `json:"active_exec_count"`
	NetworkPolicy   config.NetworkConfig  `json:"network_policy"`
	SecurityPolicy  config.SecurityConfig `json:"security_policy"`
}

func (e *Engine) Status(sessID string) (interface{}, error) {
	if sessID != "" {
		s, err := e.sessMgr.GetSession(sessID)
		if err != nil {
			return nil, err
		}
		return PublicStatus{
			SessionID:       s.ID,
			Mode:            string(s.Mode),
			Status:          string(s.Status),
			CreatedAt:       s.CreatedAt,
			ExpiresAt:       s.ExpiresAt,
			ActiveExecCount: s.ActiveExecCount,
			NetworkPolicy:   s.NetworkPolicy,
			SecurityPolicy:  s.SecurityPolicy,
		}, nil
	}

	sessions := e.sessMgr.ListSessions()
	var publicList []PublicStatus
	for _, s := range sessions {
		publicList = append(publicList, PublicStatus{
			SessionID:       s.ID,
			Mode:            string(s.Mode),
			Status:          string(s.Status),
			CreatedAt:       s.CreatedAt,
			ExpiresAt:       s.ExpiresAt,
			ActiveExecCount: s.ActiveExecCount,
			NetworkPolicy:   s.NetworkPolicy,
			SecurityPolicy:  s.SecurityPolicy,
		})
	}
	return publicList, nil
}

// ExportFile streams the opened regular file directly via /usr/local/bin/sandbox-fs export into a host destination created with O_CREATE|O_EXCL mode 0600.
func (e *Engine) ExportFile(ctx context.Context, sessID, scratchPath, destName string) (interface{}, error) {
	if !e.cfg.Security.AllowExport {
		return nil, ErrExportDisabled
	}

	cleanScratch, err := pathsafe.ValidateContainerPathUnderAllowed(scratchPath, []string{"/scratch"})
	if err != nil {
		return nil, fmt.Errorf("export denied for path '%s': %w", scratchPath, err)
	}

	// Validate destination name strictly: permit report.json, reject separators, .., UNC, control chars
	if destName == "" {
		destName = path.Base(cleanScratch)
	}
	destBase := filepath.Base(filepath.Clean(destName))
	if strings.ContainsAny(destName, "/\\:") || destName == "." || destName == ".." || destBase != destName || strings.HasPrefix(destName, ".") {
		return nil, fmt.Errorf("invalid destination name '%s'", destName)
	}

	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(e.cfg.ExportDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create export directory: %w", err)
	}

	hostDest := filepath.Join(e.cfg.ExportDir, destName)
	cleanDest, err := pathsafe.ValidateHostPathUnderRoot(hostDest, e.cfg.ExportDir)
	if err != nil {
		return nil, fmt.Errorf("export destination path unsafe: %w", err)
	}

	// Host temp file created with O_CREATE | O_EXCL mode 0600
	tempDest := fmt.Sprintf("%s.tmp_%d", cleanDest, time.Now().UnixNano())
	outFlags := os.O_CREATE | os.O_WRONLY | os.O_EXCL
	outFile, err := os.OpenFile(tempDest, outFlags, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create host export temp file: %w", err)
	}

	hasher := sha256.New()
	mw := io.MultiWriter(outFile, hasher)

	// Direct argv execution of sandbox-fs export streaming binary stdout to MultiWriter
	argv := []string{"/usr/local/bin/sandbox-fs", "export", cleanScratch}
	timeoutSec := 30
	timeout := time.Duration(timeoutSec) * time.Second

	releaseLease, leaseErr := e.sessMgr.AcquireExecLease(ctx, sessID)
	if leaseErr != nil {
		_ = outFile.Close()
		_ = os.Remove(tempDest)
		return nil, fmt.Errorf("export execution lease denied: %w", leaseErr)
	}

	exitCode, stderrMsg, timedOut, _, execErr := e.dockerClient.ExecArgvWithBinaryStdoutInRunner(
		ctx,
		sess.ComposeProject,
		sess.ComposeFilePath,
		"/scratch",
		argv,
		nil,
		nil,
		timeout,
		mw,
		e.cfg.Limits.MaximumExportBytes,
	)
	releaseLease()

	if execErr != nil || exitCode != 0 || timedOut {
		_ = outFile.Close()
		_ = os.Remove(tempDest)
		return nil, fmt.Errorf("export streaming failed (exit code %d, stderr: %s): %v", exitCode, stderrMsg, execErr)
	}

	_ = outFile.Sync()
	_ = outFile.Close()

	// Atomically publish completed export
	if err := os.Rename(tempDest, cleanDest); err != nil {
		_ = os.Remove(tempDest)
		return nil, fmt.Errorf("failed to publish completed export file: %w", err)
	}

	shaHex := hex.EncodeToString(hasher.Sum(nil))
	info, _ := os.Stat(cleanDest)
	fileBytes := int64(0)
	if info != nil {
		fileBytes = info.Size()
	}

	return map[string]interface{}{
		"session_id":  sessID,
		"source_path": cleanScratch,
		"export_path": cleanDest,
		"sha256":      shaHex,
		"bytes":       fileBytes,
	}, nil
}

func (e *Engine) StopSession(ctx context.Context, sessID string) error {
	summary, err := e.cleanupSession(ctx, sessID)
	if err != nil {
		return fmt.Errorf("StopSession failed: %w (summary: %+v)", err, summary)
	}
	return nil
}

// cleanupSession is the single transactional cleanup function used by all stop, failure, and reset paths.
func (e *Engine) cleanupSession(ctx context.Context, sessID string) (session.CleanupSummary, error) {
	summary := session.CleanupSummary{CleanupRetryable: true}

	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		summary.CleanupError = err.Error()
		return summary, err
	}

	snap := docker.ResourceSnapshot{
		RunnerContainerID: sess.RunnerContainerID,
		NetworkID:         sess.NetworkID,
		ScratchVolumeName: sess.VolumeName,
		ComposeProject:    sess.ComposeProject,
	}

	downCtx, downCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer downCancel()

	// 1. Inspect present resources & verify ownership
	insp, inspErr := e.dockerClient.InspectResources(downCtx, sess.ComposeProject, sess.ID, snap)
	if inspErr != nil {
		summary.CleanupError = fmt.Sprintf("resource inspection failed: %v", inspErr)
		e.recordCleanupFailure(sessID, summary)
		return summary, inspErr
	}

	if (insp.Runner.Present && !insp.Runner.OwnershipVerified) ||
		(insp.Network.Present && !insp.Network.OwnershipVerified) ||
		(insp.ScratchVolume.Present && !insp.ScratchVolume.OwnershipVerified) {
		summary.CleanupError = "mismatching present resource detected, cleanup halted"
		e.recordCleanupFailure(sessID, summary)
		return summary, errors.New(summary.CleanupError)
	}

	// 2. Mark session stopping and wait for active exec leases to complete
	if err := e.sessMgr.BeginStopping(downCtx, sessID); err != nil {
		summary.CleanupError = fmt.Sprintf("failed to begin stopping session: %v", err)
		e.recordCleanupFailure(sessID, summary)
		return summary, err
	}

	// 3. Run Docker ComposeDown to remove present matching resources
	downErr := e.dockerClient.ComposeDown(downCtx, sess.ComposeProject, sess.ComposeFilePath)

	// 4. Verify resources absent (FAIL CLOSED) using a fresh context
	absCtx, absCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer absCancel()

	runnerRemoved, networkRemoved, scratchRemoved, absErr := e.dockerClient.VerifyResourcesAbsent(absCtx, sess.ComposeProject, sess.ID, snap)
	summary.RunnerRemoved = runnerRemoved
	summary.NetworkRemoved = networkRemoved
	summary.ScratchRemoved = scratchRemoved

	if absErr != nil || downErr != nil || !runnerRemoved || !networkRemoved || !scratchRemoved {
		summary.CleanupError = fmt.Sprintf("docker cleanup incomplete (absErr: %v, downErr: %v, runner: %v, net: %v, vol: %v)", absErr, downErr, runnerRemoved, networkRemoved, scratchRemoved)
		e.recordCleanupFailure(sessID, summary)
		return summary, fmt.Errorf("cleanup incomplete for session %s", sessID)
	}

	// 5. Remove session state ONLY when all owned resources are confirmed absent
	if err := e.sessMgr.RemoveSession(sessID); err != nil {
		summary.CleanupError = fmt.Sprintf("failed to remove state directory: %v", err)
		e.recordCleanupFailure(sessID, summary)
		return summary, err
	}

	summary.StateRemoved = true
	summary.CleanupRetryable = false

	if e.auditLogger != nil {
		_ = e.auditLogger.Log(audit.Event{
			SessionID:     sessID,
			Interface:     "engine",
			ToolOrCommand: "sandbox_stop",
			AuditMode:     audit.AuditMetadataOnly,
		})
	}

	return summary, nil
}

func (e *Engine) rollbackStartup(ctx context.Context, sessID string) {
	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return
	}

	snap := docker.ResourceSnapshot{
		RunnerContainerID: sess.RunnerContainerID,
		NetworkID:         sess.NetworkID,
		ScratchVolumeName: sess.VolumeName,
		ComposeProject:    sess.ComposeProject,
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(e.cfg.Limits.ShutdownGraceSeconds)*time.Second)
	defer cancel()

	_ = e.dockerClient.ComposeDown(cleanupCtx, sess.ComposeProject, sess.ComposeFilePath)
	rRem, nRem, sRem, _ := e.dockerClient.VerifyResourcesAbsent(cleanupCtx, sess.ComposeProject, sess.ID, snap)

	if rRem && nRem && sRem {
		_ = e.sessMgr.RemoveSession(sessID)
	} else {
		e.recordCleanupFailure(sessID, session.CleanupSummary{
			RunnerRemoved:    rRem,
			NetworkRemoved:   nRem,
			ScratchRemoved:   sRem,
			CleanupError:     "startup rollback incomplete",
			CleanupRetryable: true,
		})
	}
}

func (e *Engine) recordCleanupFailure(sessID string, summary session.CleanupSummary) {
	_ = e.sessMgr.UpdateSessionState(sessID, func(s *session.Session) {
		s.Status = session.StateCleanupFailed
		s.CleanupState = "cleanup-failed"
		s.CleanupError = summary.CleanupError
		s.CleanupTimestamp = time.Now().UTC().Format(time.RFC3339)
		s.CleanupRetryable = true
		s.Cleanup = summary
	})
}

func (e *Engine) ResetSession(ctx context.Context, sessID string) (*StartResult, error) {
	sess, err := e.sessMgr.GetSession(sessID)
	outbound := e.cfg.Network.OutboundEnabled
	hostAccess := e.cfg.Network.HostGatewayEnabled
	if err == nil {
		outbound = sess.OutboundEnabled
		hostAccess = sess.HostGatewayEnabled
	}

	if err := e.StopSession(ctx, sessID); err != nil {
		return nil, fmt.Errorf("cannot reset session: StopSession failed: %w", err)
	}

	outboundPtr := &outbound
	hostAccessPtr := &hostAccess
	return e.StartSession(ctx, outboundPtr, hostAccessPtr, e.cfg.Limits.DefaultSessionTTLMinutes)
}

func (e *Engine) GetAuditSummary(sessionID string, limit int) ([]audit.Event, error) {
	if e.auditLogger == nil {
		return []audit.Event{}, nil
	}
	return e.auditLogger.GetSummaryForSession(sessionID, limit)
}

func (e *Engine) resolveNetworkPolicy(requested *bool, globalConfig bool, name string) (bool, error) {
	if requested == nil {
		return globalConfig, nil
	}
	if !*requested {
		return false, nil
	}
	if *requested && globalConfig {
		return true, nil
	}
	return false, fmt.Errorf("%w: requested %s=true, but global policy is false", ErrPolicyDenied, name)
}

func (e *Engine) clampTimeout(userTimeout int) int {
	if userTimeout <= 0 {
		return e.cfg.Limits.DefaultTimeoutSeconds
	}
	if userTimeout > e.cfg.Limits.MaximumTimeoutSeconds {
		return e.cfg.Limits.MaximumTimeoutSeconds
	}
	return userTimeout
}
