package lab

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
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

type CleanupSummary struct {
	RunnerRemoved  bool `json:"runner_removed"`
	ScratchRemoved bool `json:"scratch_removed"`
	NetworkRemoved bool `json:"network_removed"`
}

type RunResult struct {
	SessionID       string         `json:"session_id"`
	Ephemeral       bool           `json:"ephemeral"`
	ExitCode        int            `json:"exit_code"`
	TimedOut        bool           `json:"timed_out"`
	DurationMS      int64          `json:"duration_ms"`
	Stdout          string         `json:"stdout"`
	Stderr          string         `json:"stderr"`
	StdoutTruncated bool           `json:"stdout_truncated"`
	StderrTruncated bool           `json:"stderr_truncated"`
	Cleanup         CleanupSummary `json:"cleanup"`
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

	// Defer verified auto-cleanup using independent bounded context
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(e.cfg.Limits.ShutdownGraceSeconds)*time.Second)
		defer cancel()

		downErr := e.dockerClient.ComposeDown(cleanupCtx, sess.ComposeProject, sess.ComposeFilePath)
		removeErr := e.sessMgr.RemoveSession(sess.ID)

		success := downErr == nil && removeErr == nil
		res.Cleanup = CleanupSummary{
			RunnerRemoved:  success,
			ScratchRemoved: success,
			NetworkRemoved: success,
		}
	}()

	_ = e.sessMgr.Transition(sess.ID, session.StateCreated, session.StateStarting)

	composeContent, err := docker.GenerateComposeYAML(sess.ID, sess.OutboundEnabled, sess.HostGatewayEnabled, e.cfg)
	if err != nil {
		return res, fmt.Errorf("failed to generate compose configuration: %w", err)
	}

	if err := os.WriteFile(sess.ComposeFilePath, []byte(composeContent), 0600); err != nil {
		return res, fmt.Errorf("failed to write compose file: %w", err)
	}

	if err := e.dockerClient.ComposeUp(ctx, sess.ComposeProject, sess.ComposeFilePath); err != nil {
		return res, fmt.Errorf("failed to bring up runner container: %w", err)
	}

	_ = e.sessMgr.Transition(sess.ID, session.StateStarting, session.StateReady)

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
	effectiveHostAccess, err := e.resolveNetworkPolicy(reqHostAccess, e.cfg.Network.HostGatewayEnabled, "host_access")
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
		_ = e.sessMgr.RemoveSession(sess.ID)
		return nil, fmt.Errorf("failed to generate compose yaml: %w", err)
	}

	if err := os.WriteFile(sess.ComposeFilePath, []byte(composeContent), 0600); err != nil {
		_ = e.sessMgr.RemoveSession(sess.ID)
		return nil, fmt.Errorf("failed to write compose file: %w", err)
	}

	if err := e.dockerClient.ComposeUp(ctx, sess.ComposeProject, sess.ComposeFilePath); err != nil {
		_ = e.dockerClient.ComposeDown(ctx, sess.ComposeProject, sess.ComposeFilePath)
		_ = e.sessMgr.RemoveSession(sess.ID)
		return nil, fmt.Errorf("docker compose up failed: %w", err)
	}

	_ = e.sessMgr.Transition(sess.ID, session.StateStarting, session.StateReady)

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

	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return nil, err
	}

	if sess.Status != session.StateReady && sess.Status != session.StateRunningCommand {
		return nil, fmt.Errorf("session %s is in state '%s', cannot execute command", sessID, sess.Status)
	}

	if cwd == "" {
		cwd = "/scratch"
	}
	cleanCwd, err := pathsafe.ValidateContainerPathUnderAllowed(cwd, []string{"/scratch", "/tmp"})
	if err != nil {
		return nil, fmt.Errorf("invalid execution working directory: %w", err)
	}

	releaseSem, err := e.sessMgr.AcquireExecSemaphores(ctx, sessID)
	if err != nil {
		return nil, fmt.Errorf("concurrency limit exceeded: %w", err)
	}
	defer releaseSem()

	_ = e.sessMgr.SetActiveExecCount(sessID, 1)
	defer func() { _ = e.sessMgr.SetActiveExecCount(sessID, -1) }()

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
	DurationMS             int64               `json:"duration_ms"`
	RedirectChain          []string            `json:"redirect_chain"`
	CurlExitCode           int                 `json:"curl_exit_code"`
	ErrorCategory          string              `json:"error_category,omitempty"`
	HostGatewayTranslation bool                `json:"host_gateway_translation"`
	ConnectionHost         string              `json:"connection_host"`
	Truncated              bool                `json:"truncated"`
}

// HTTPRequest executes a structured HTTP request using the trusted compiled sandbox-http Go helper binary.
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
		"host_gateway_enabled": e.cfg.Network.HostGatewayEnabled,
		"max_response_bytes":   e.cfg.Limits.MaximumReadBytes,
	}

	specData, err := json.Marshal(specObj)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize HTTP request specification: %w", err)
	}

	specB64 := base64.StdEncoding.EncodeToString(specData)
	execCmd := fmt.Sprintf("echo '%s' | base64 -d | /usr/local/bin/sandbox-http", specB64)

	var execRes *ExecResult
	if opts.SessionID != "" {
		execRes, err = e.Exec(ctx, opts.SessionID, execCmd, "/scratch", opts.TimeoutSeconds, nil)
	} else {
		runRes, err := e.Run(ctx, execCmd, "/scratch", opts.TimeoutSeconds, nil)
		if err == nil {
			execRes = &ExecResult{
				SessionID:       runRes.SessionID,
				ExitCode:        runRes.ExitCode,
				TimedOut:        runRes.TimedOut,
				DurationMS:      runRes.DurationMS,
				Stdout:          runRes.Stdout,
				Stderr:          runRes.Stderr,
				StdoutTruncated: runRes.StdoutTruncated,
			}
		} else {
			return nil, err
		}
	}

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
			ExitCode:      &resDoc.CurlExitCode,
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

	if maxBytes <= 0 {
		maxBytes = e.cfg.Limits.MaximumReadBytes
	}

	cmd := fmt.Sprintf("/usr/local/bin/sandbox-fs read '%s' %d %d", cleanPath, offset, maxBytes)
	res, err := e.Exec(ctx, sessID, cmd, "/scratch", 15, nil)
	if err != nil || res.ExitCode != 0 {
		return nil, fmt.Errorf("sandbox-fs read failed for '%s': exit code %d, stderr: %s", cleanPath, res.ExitCode, res.Stderr)
	}

	content := res.Stdout
	encoding := "utf-8"
	if binaryEncoding == "base64" {
		content = base64.StdEncoding.EncodeToString([]byte(res.Stdout))
		encoding = "base64"
	}

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
		Encoding:  encoding,
		Truncated: res.StdoutTruncated,
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

	b64Data := base64.StdEncoding.EncodeToString([]byte(content))
	overwriteStr := "false"
	if overwrite {
		overwriteStr = "true"
	}

	cmd := fmt.Sprintf("echo '%s' | base64 -d | /usr/local/bin/sandbox-fs write '%s' %s", b64Data, cleanPath, overwriteStr)
	res, err := e.Exec(ctx, sessID, cmd, "/scratch", 15, nil)
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

func (e *Engine) ExportFile(ctx context.Context, sessID, scratchPath, destName string) (interface{}, error) {
	if !e.cfg.Security.AllowExport {
		return nil, ErrExportDisabled
	}

	cleanScratch, err := pathsafe.ValidateContainerPathUnderAllowed(scratchPath, []string{"/scratch"})
	if err != nil {
		return nil, fmt.Errorf("export denied for path '%s': %w", scratchPath, err)
	}

	// Verify regular file via sandbox-fs stat before export
	statCmd := fmt.Sprintf("/usr/local/bin/sandbox-fs stat '%s'", cleanScratch)
	statRes, err := e.Exec(ctx, sessID, statCmd, "/scratch", 10, nil)
	if err != nil || statRes.ExitCode != 0 {
		return nil, fmt.Errorf("failed to stat export source file '%s': %v", cleanScratch, err)
	}

	var statObj map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(statRes.Stdout)), &statObj); err != nil {
		return nil, fmt.Errorf("failed to parse sandbox-fs stat output: %w", err)
	}

	if isRegular, ok := statObj["is_regular"].(bool); !ok || !isRegular {
		return nil, fmt.Errorf("export source '%s' is not a regular file", cleanScratch)
	}

	fileSizeFloat, _ := statObj["size"].(float64)
	if int64(fileSizeFloat) > e.cfg.Limits.MaximumExportBytes {
		return nil, fmt.Errorf("file size %d exceeds maximum export limit %d", int64(fileSizeFloat), e.cfg.Limits.MaximumExportBytes)
	}

	if destName == "" {
		destName = path.Base(cleanScratch)
	}
	destName = filepath.Base(filepath.Clean(destName))
	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return nil, err
	}

	// Duplicate-safe destination naming
	hostDest := filepath.Join(e.cfg.ExportDir, destName)
	if _, err := os.Stat(hostDest); err == nil {
		ext := filepath.Ext(destName)
		base := strings.TrimSuffix(destName, ext)
		destName = fmt.Sprintf("%s_%d%s", base, time.Now().UnixNano(), ext)
		hostDest = filepath.Join(e.cfg.ExportDir, destName)
	}

	cleanDest, err := pathsafe.ValidateHostPathUnderRoot(hostDest, e.cfg.ExportDir)
	if err != nil {
		return nil, fmt.Errorf("export destination path unsafe: %w", err)
	}

	if err := e.dockerClient.CopyFileFromRunner(ctx, sess.ComposeProject, cleanScratch, cleanDest); err != nil {
		return nil, fmt.Errorf("failed to export file from container: %w", err)
	}

	data, err := os.ReadFile(cleanDest)
	if err != nil {
		return nil, fmt.Errorf("failed to read exported file for hashing: %w", err)
	}

	hash := sha256.Sum256(data)
	shaHex := hex.EncodeToString(hash[:])

	return map[string]interface{}{
		"session_id":  sessID,
		"source_path": cleanScratch,
		"export_path": cleanDest,
		"sha256":      shaHex,
		"bytes":       int64(len(data)),
	}, nil
}

func (e *Engine) StopSession(ctx context.Context, sessID string) error {
	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return err
	}

	// Verify resource ownership before destructive removal; ABORT IF VERIFICATION FAILS
	if err := e.dockerClient.VerifyResourceOwnership(ctx, sess.ComposeProject, sess.ID); err != nil {
		_ = e.sessMgr.UpdateSessionState(sessID, func(s *session.Session) {
			s.Status = session.StateCleanupFailed
			s.CleanupState = "cleanup-failed"
			s.CleanupError = err.Error()
			s.CleanupTimestamp = time.Now().UTC().Format(time.RFC3339)
		})
		return fmt.Errorf("ownership verification failed for session %s: %w", sessID, err)
	}

	_ = e.sessMgr.Transition(sessID, "", session.StateStopping)

	cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Duration(e.cfg.Limits.ShutdownGraceSeconds)*time.Second)
	defer cancel()

	if err := e.dockerClient.ComposeDown(cleanupCtx, sess.ComposeProject, sess.ComposeFilePath); err != nil {
		_ = e.sessMgr.UpdateSessionState(sessID, func(s *session.Session) {
			s.Status = session.StateCleanupFailed
			s.CleanupState = "cleanup-failed"
			s.CleanupError = err.Error()
			s.CleanupTimestamp = time.Now().UTC().Format(time.RFC3339)
		})
		return fmt.Errorf("failed to stop session containers: %w", err)
	}

	if err := e.sessMgr.RemoveSession(sessID); err != nil {
		_ = e.sessMgr.UpdateSessionState(sessID, func(s *session.Session) {
			s.Status = session.StateCleanupFailed
			s.CleanupState = "cleanup-failed"
			s.CleanupError = err.Error()
			s.CleanupTimestamp = time.Now().UTC().Format(time.RFC3339)
		})
		return fmt.Errorf("failed to remove session state directory: %w", err)
	}

	if e.auditLogger != nil {
		_ = e.auditLogger.Log(audit.Event{
			SessionID:     sessID,
			Interface:     "engine",
			ToolOrCommand: "sandbox_stop",
			AuditMode:     audit.AuditMetadataOnly,
		})
	}

	return nil
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
