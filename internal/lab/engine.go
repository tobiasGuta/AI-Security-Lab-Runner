package lab

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ai-security-lab-runner/lab-runner/internal/audit"
	"github.com/ai-security-lab-runner/lab-runner/internal/config"
	"github.com/ai-security-lab-runner/lab-runner/internal/docker"
	"github.com/ai-security-lab-runner/lab-runner/internal/manifest"
	"github.com/ai-security-lab-runner/lab-runner/internal/pathsafe"
	"github.com/ai-security-lab-runner/lab-runner/internal/session"
)

var (
	ErrExportDisabled     = errors.New("file export is disabled by security policy")
	ErrInvalidScratchPath = errors.New("write is restricted strictly to /scratch descendants")
	ErrExecutionDenied    = errors.New("command execution denied")
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

type ProjectInfo struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	Path            string `json:"path"`
	ManifestVersion int    `json:"manifest_version"`
	IsValid         bool   `json:"is_valid"`
	ValidationError string `json:"validation_error,omitempty"`
}

func (e *Engine) ListProjects() ([]ProjectInfo, error) {
	entries, err := os.ReadDir(e.cfg.LabRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to read lab_root directory '%s': %w", e.cfg.LabRoot, err)
	}

	var projects []ProjectInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		labDir := filepath.Join(e.cfg.LabRoot, entry.Name())
		info := ProjectInfo{
			Name: entry.Name(),
			Path: entry.Name(),
		}

		mfs, err := manifest.LoadManifest(labDir)
		if err != nil {
			info.IsValid = false
			info.ValidationError = err.Error()
		} else {
			info.IsValid = true
			info.Description = mfs.Description
			info.ManifestVersion = mfs.Version
		}
		projects = append(projects, info)
	}

	return projects, nil
}

type StartResult struct {
	SessionID    string            `json:"session_id"`
	Project      string            `json:"project"`
	InternalURLs map[string]string `json:"internal_urls"`
	Status       string            `json:"status"`
	ExpiresAt    time.Time         `json:"expires_at"`
}

func (e *Engine) StartSession(ctx context.Context, projectIdentifier string, rebuild bool) (*StartResult, error) {
	cleanProj, err := pathsafe.CleanHostPath(projectIdentifier)
	if err != nil {
		return nil, fmt.Errorf("invalid project identifier: %w", err)
	}

	labDir := filepath.Join(e.cfg.LabRoot, cleanProj)
	validatedLabDir, err := pathsafe.ValidateHostPathUnderRoot(labDir, e.cfg.LabRoot)
	if err != nil {
		return nil, fmt.Errorf("project path unsafe: %w", err)
	}

	mfs, err := manifest.LoadManifest(validatedLabDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load lab manifest: %w", err)
	}

	sess, err := e.sessMgr.CreateSession(mfs)
	if err != nil {
		return nil, err
	}

	_ = e.sessMgr.Transition(sess.ID, session.StateCreated, session.StateStarting)

	composeContent, err := docker.GenerateComposeYAML(sess.ID, mfs, e.cfg, validatedLabDir)
	if err != nil {
		_ = e.sessMgr.RemoveSession(sess.ID)
		return nil, fmt.Errorf("failed to generate compose yaml: %w", err)
	}

	if err := os.WriteFile(sess.ComposeFilePath, []byte(composeContent), 0600); err != nil {
		_ = e.sessMgr.RemoveSession(sess.ID)
		return nil, fmt.Errorf("failed to write compose file: %w", err)
	}

	if err := e.dockerClient.ComposeUp(ctx, sess.ComposeProject, sess.ComposeFilePath); err != nil {
		if e.cfg.Security.RemoveSessionOnStartFailure {
			_ = e.dockerClient.ComposeDown(ctx, sess.ComposeProject, sess.ComposeFilePath)
			_ = e.sessMgr.RemoveSession(sess.ID)
		} else {
			_ = e.sessMgr.Transition(sess.ID, session.StateStarting, session.StateFailed)
		}
		return nil, fmt.Errorf("docker compose up failed: %w", err)
	}

	_ = e.sessMgr.Transition(sess.ID, session.StateStarting, session.StateHealthy)

	internalURLs := make(map[string]string)
	for _, target := range mfs.Targets {
		if target.InternalPort > 0 {
			internalURLs[target.Name] = fmt.Sprintf("http://%s:%d", target.Name, target.InternalPort)
		}
	}

	if e.auditLogger != nil {
		_ = e.auditLogger.Log(audit.Event{
			SessionID:     sess.ID,
			Project:       mfs.Name,
			Interface:     "engine",
			ToolOrCommand: "lab_start",
			Resources:     []string{sess.ComposeProject},
		})
	}

	return &StartResult{
		SessionID:    sess.ID,
		Project:      mfs.Name,
		InternalURLs: internalURLs,
		Status:       string(session.StateHealthy),
		ExpiresAt:    sess.ExpiresAt,
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
	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return nil, err
	}

	if sess.Status != session.StateHealthy && sess.Status != session.StateRunningCommand {
		return nil, fmt.Errorf("session %s is in state '%s', cannot execute command", sessID, sess.Status)
	}

	if cwd == "" {
		cwd = "/workspace"
	}
	cleanCwd, err := pathsafe.ValidateContainerPathUnderAllowed(cwd, []string{"/workspace", "/scratch", "/tmp"})
	if err != nil {
		return nil, fmt.Errorf("invalid execution working directory: %w", err)
	}

	lock, err := e.sessMgr.GetExecLock(sessID)
	if err != nil {
		return nil, err
	}
	lock.Lock()
	defer lock.Unlock()

	timeout := time.Duration(timeoutSec) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(e.cfg.Limits.DefaultTimeoutSeconds) * time.Second
	}
	maxTimeout := time.Duration(e.cfg.Limits.MaximumTimeoutSeconds) * time.Second
	if timeout > maxTimeout {
		timeout = maxTimeout
	}

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
			Project:         sess.Project,
			Interface:       "engine",
			ToolOrCommand:   "lab_exec",
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

type ReadResult struct {
	SessionID string `json:"session_id"`
	Path      string `json:"path"`
	Content   string `json:"content"`
	Encoding  string `json:"encoding"`
	Truncated bool   `json:"truncated"`
}

func (e *Engine) ReadFile(ctx context.Context, sessID, containerPath string, offset int64, maxBytes int64) (*ReadResult, error) {
	cleanPath, err := pathsafe.ValidateContainerPathUnderAllowed(containerPath, []string{"/workspace", "/scratch"})
	if err != nil {
		return nil, fmt.Errorf("read path denied: %w", err)
	}

	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return nil, err
	}

	if maxBytes <= 0 {
		maxBytes = e.cfg.Limits.MaximumReadBytes
	}

	// Read via base64 encoded cat in runner container
	cmd := fmt.Sprintf("base64 -w 0 '%s'", cleanPath)
	res, err := e.Exec(ctx, sess.ID, cmd, "/workspace", 15, nil)
	if err != nil || res.ExitCode != 0 {
		return nil, fmt.Errorf("failed to read container file '%s': exit code %d, stderr: %s", cleanPath, res.ExitCode, res.Stderr)
	}

	rawBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(res.Stdout))
	if err != nil {
		return nil, fmt.Errorf("failed to decode container file content: %w", err)
	}

	if offset > 0 && offset < int64(len(rawBytes)) {
		rawBytes = rawBytes[offset:]
	}

	truncated := false
	if int64(len(rawBytes)) > maxBytes {
		rawBytes = rawBytes[:maxBytes]
		truncated = true
	}

	return &ReadResult{
		SessionID: sessID,
		Path:      cleanPath,
		Content:   string(rawBytes),
		Encoding:  "utf-8",
		Truncated: truncated,
	}, nil
}

type WriteResult struct {
	SessionID      string `json:"session_id"`
	NormalizedPath string `json:"normalized_path"`
	BytesWritten   int64  `json:"bytes_written"`
}

// Invariant 5: Scratch is the only persistent writable agent directory.
func (e *Engine) WriteScratch(ctx context.Context, sessID, scratchPath, content, encoding string, overwrite bool) (*WriteResult, error) {
	cleanPath, err := pathsafe.ValidateContainerPathUnderAllowed(scratchPath, []string{"/scratch"})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidScratchPath, err)
	}

	if cleanPath == "/scratch" || cleanPath == "/scratch/" {
		return nil, fmt.Errorf("%w: cannot write directly to root /scratch as a file", ErrInvalidScratchPath)
	}

	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return nil, err
	}

	if int64(len(content)) > e.cfg.Limits.MaximumWriteBytes {
		return nil, fmt.Errorf("content size %d exceeds write limit %d", len(content), e.cfg.Limits.MaximumWriteBytes)
	}

	b64Data := base64.StdEncoding.EncodeToString([]byte(content))
	dir := path.Dir(cleanPath)

	var cmd string
	if overwrite {
		cmd = fmt.Sprintf("mkdir -p '%s' && echo '%s' | base64 -d > '%s'", dir, b64Data, cleanPath)
	} else {
		cmd = fmt.Sprintf("mkdir -p '%s' && if [ -f '%s' ]; then exit 17; else echo '%s' | base64 -d > '%s'; fi", dir, cleanPath, b64Data, cleanPath)
	}

	res, err := e.Exec(ctx, sess.ID, cmd, "/scratch", 15, nil)
	if err != nil || res.ExitCode != 0 {
		if res != nil && res.ExitCode == 17 {
			return nil, fmt.Errorf("file '%s' already exists and overwrite is false", cleanPath)
		}
		return nil, fmt.Errorf("failed to write file '%s' in scratch: %s", cleanPath, res.Stderr)
	}

	return &WriteResult{
		SessionID:      sessID,
		NormalizedPath: cleanPath,
		BytesWritten:   int64(len(content)),
	}, nil
}

type ExportResult struct {
	SessionID   string `json:"session_id"`
	SourcePath  string `json:"source_path"`
	ExportPath  string `json:"export_path"`
	SHA256Check string `json:"sha256"`
	Bytes       int64  `json:"bytes"`
}

// Invariant 8: Export is disabled by default.
func (e *Engine) ExportFile(ctx context.Context, sessID, scratchPath, destName string) (*ExportResult, error) {
	if !e.cfg.Security.AllowExport {
		return nil, ErrExportDisabled
	}

	cleanScratch, err := pathsafe.ValidateContainerPathUnderAllowed(scratchPath, []string{"/scratch"})
	if err != nil {
		return nil, fmt.Errorf("export denied for path '%s': %w", scratchPath, err)
	}

	if destName == "" {
		destName = path.Base(cleanScratch)
	}
	if strings.ContainsAny(destName, "/\\..") {
		return nil, fmt.Errorf("invalid destination name '%s'", destName)
	}

	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return nil, err
	}

	hostDest := filepath.Join(e.cfg.ExportDir, destName)
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

	if int64(len(data)) > e.cfg.Limits.MaximumExportBytes {
		_ = os.Remove(cleanDest)
		return nil, fmt.Errorf("exported file exceeds size limit %d", e.cfg.Limits.MaximumExportBytes)
	}

	hash := sha256.Sum256(data)
	shaHex := hex.EncodeToString(hash[:])

	if e.auditLogger != nil {
		_ = e.auditLogger.Log(audit.Event{
			SessionID:     sessID,
			Project:       sess.Project,
			Interface:     "engine",
			ToolOrCommand: "lab_export_file",
			Resources:     []string{cleanDest},
		})
	}

	return &ExportResult{
		SessionID:   sessID,
		SourcePath:  cleanScratch,
		ExportPath:  cleanDest,
		SHA256Check: shaHex,
		Bytes:       int64(len(data)),
	}, nil
}

func (e *Engine) StopSession(ctx context.Context, sessID string) error {
	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return err
	}

	_ = e.sessMgr.Transition(sessID, "", session.StateStopping)
	_ = e.dockerClient.ComposeDown(ctx, sess.ComposeProject, sess.ComposeFilePath)
	_ = e.sessMgr.RemoveSession(sessID)

	if e.auditLogger != nil {
		_ = e.auditLogger.Log(audit.Event{
			SessionID:     sessID,
			Project:       sess.Project,
			Interface:     "engine",
			ToolOrCommand: "lab_stop",
		})
	}

	return nil
}

func (e *Engine) ResetSession(ctx context.Context, sessID string, rebuild bool) (*StartResult, error) {
	sess, err := e.sessMgr.GetSession(sessID)
	if err != nil {
		return nil, err
	}

	proj := sess.Project
	_ = e.StopSession(ctx, sessID)

	return e.StartSession(ctx, proj, rebuild)
}

func (e *Engine) GetSessionStatus(sessID string) (*session.Session, error) {
	return e.sessMgr.GetSession(sessID)
}

func (e *Engine) ListSessions() []*session.Session {
	return e.sessMgr.ListSessions()
}
