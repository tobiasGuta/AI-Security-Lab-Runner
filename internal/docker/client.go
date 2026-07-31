package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/output"
)

var (
	ErrDockerUnavailable = errors.New("docker is unavailable")
	ErrDockerExecFailed  = errors.New("docker execution failed")
	ErrResourceMismatch  = errors.New("resource ownership mismatch")
)

type Client interface {
	CheckDockerAvailable(ctx context.Context) error
	CheckComposeAvailable(ctx context.Context) error
	CheckLinuxContainers(ctx context.Context) error
	BuildImage(ctx context.Context, dockerfilePath, imageTag string) error
	ComposeUp(ctx context.Context, projectName, composeFilePath string) error
	ComposeDown(ctx context.Context, projectName, composeFilePath string) error
	ExecInRunner(ctx context.Context, projectName, composeFilePath, cwd, cmd string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error)
	CopyFileFromRunner(ctx context.Context, projectName, scratchContainerPath, hostDestPath string) error
	ListManagedResources(ctx context.Context) ([]string, error)
	VerifyResourceOwnership(ctx context.Context, projectName, sessionID string) error
}

type CLIClient struct {
	dockerBin string
}

func NewCLIClient() *CLIClient {
	return &CLIClient{
		dockerBin: "docker",
	}
}

func (c *CLIClient) runDockerCmd(ctx context.Context, args ...string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, c.dockerBin, args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return stdoutBuf.String(), stderrBuf.String(), exitCode, err
}

func (c *CLIClient) CheckDockerAvailable(ctx context.Context) error {
	_, stderr, exitCode, err := c.runDockerCmd(ctx, "info")
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: docker info failed (exit code %d): %s", ErrDockerUnavailable, exitCode, stderr)
	}
	return nil
}

func (c *CLIClient) CheckComposeAvailable(ctx context.Context) error {
	_, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "version")
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: docker compose version failed: %s", ErrDockerUnavailable, stderr)
	}
	return nil
}

func (c *CLIClient) CheckLinuxContainers(ctx context.Context) error {
	stdout, _, exitCode, err := c.runDockerCmd(ctx, "info", "--format", "{{.OSType}}")
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: failed to check OSType", ErrDockerUnavailable)
	}
	osType := strings.TrimSpace(stdout)
	if osType != "linux" {
		return fmt.Errorf("%w: Docker is configured for '%s' containers, but 'linux' containers are required", ErrDockerUnavailable, osType)
	}
	return nil
}

func (c *CLIClient) BuildImage(ctx context.Context, dockerfilePath, imageTag string) error {
	dir := filepathDir(dockerfilePath)
	_, stderr, exitCode, err := c.runDockerCmd(ctx, "build", "-t", imageTag, "-f", dockerfilePath, dir)
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: docker build failed (exit code %d): %s", ErrDockerExecFailed, exitCode, stderr)
	}
	return nil
}

func (c *CLIClient) ComposeUp(ctx context.Context, projectName, composeFilePath string) error {
	_, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "-p", projectName, "-f", composeFilePath, "up", "-d")
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: docker compose up failed (exit code %d): %s", ErrDockerExecFailed, exitCode, stderr)
	}
	return nil
}

func (c *CLIClient) VerifyResourceOwnership(ctx context.Context, projectName, sessionID string) error {
	stdout, _, exitCode, err := c.runDockerCmd(ctx, "ps", "-a", "--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID), "--format", "{{.ID}}")
	if err != nil || exitCode != 0 || strings.TrimSpace(stdout) == "" {
		return fmt.Errorf("%w: verified session label %s not found on active containers", ErrResourceMismatch, sessionID)
	}
	return nil
}

func (c *CLIClient) ComposeDown(ctx context.Context, projectName, composeFilePath string) error {
	_, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "-p", projectName, "-f", composeFilePath, "down", "-v", "--remove-orphans")
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: docker compose down failed (exit code %d): %s", ErrDockerExecFailed, exitCode, stderr)
	}
	return nil
}

// Invariant 2 & Internal Timeout Enforcement: Wrap command with internal GNU timeout inside runner container.
func (c *CLIClient) ExecInRunner(ctx context.Context, projectName, composeFilePath, cwd, agentCmd string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
	// Give controller host command context a small grace period beyond internal timeout
	hostTimeout := timeout + 5*time.Second
	if timeout <= 0 {
		hostTimeout = 35 * time.Second
	}

	execCtx, cancel := context.WithTimeout(ctx, hostTimeout)
	defer cancel()

	args := []string{
		"compose", "-p", projectName, "-f", composeFilePath,
		"exec", "-T", "--workdir", cwd,
	}

	for k, v := range env {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	// Internal GNU timeout inside runner container
	timeoutSec := int(timeout.Seconds())
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	wrappedCmd := fmt.Sprintf("timeout --signal=TERM --kill-after=2s %ds bash -lc %q", timeoutSec, agentCmd)

	args = append(args, "runner", "sh", "-c", wrappedCmd)

	cmd := exec.CommandContext(execCtx, c.dockerBin, args...)

	stdoutWriter := output.NewBoundedWriter(maxOutputBytes)
	stderrWriter := output.NewBoundedWriter(maxOutputBytes)
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter

	execErr := cmd.Run()

	exitCode = 0
	if execErr != nil {
		var exitErr *exec.ExitError
		if errors.As(execErr, &exitErr) {
			exitCode = exitErr.ExitCode()
			if exitCode == 124 || exitCode == 137 {
				timedOut = true
			}
		} else if execCtx.Err() == context.DeadlineExceeded {
			timedOut = true
			exitCode = 124
		} else {
			exitCode = -1
		}
	}

	truncated = stdoutWriter.Truncated || stderrWriter.Truncated
	return exitCode, stdoutWriter.String(), stderrWriter.String(), timedOut, truncated, nil
}

func (c *CLIClient) CopyFileFromRunner(ctx context.Context, projectName, scratchContainerPath, hostDestPath string) error {
	stdout, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "-p", projectName, "ps", "-q", "runner")
	if err != nil || exitCode != 0 || strings.TrimSpace(stdout) == "" {
		return fmt.Errorf("%w: failed to get runner container ID: %s", ErrDockerExecFailed, stderr)
	}

	containerID := strings.TrimSpace(stdout)
	src := fmt.Sprintf("%s:%s", containerID, scratchContainerPath)

	_, stderr, exitCode, err = c.runDockerCmd(ctx, "cp", src, hostDestPath)
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: docker cp failed (exit code %d): %s", ErrDockerExecFailed, exitCode, stderr)
	}

	return nil
}

func (c *CLIClient) ListManagedResources(ctx context.Context) ([]string, error) {
	stdout, stderr, exitCode, err := c.runDockerCmd(ctx, "ps", "-a", "--filter", "label=ai.security.lab-runner.managed=true", "--format", "{{.ID}}\t{{.Names}}\t{{.Status}}")
	if err != nil || exitCode != 0 {
		return nil, fmt.Errorf("%w: failed to list managed containers: %s", ErrDockerExecFailed, stderr)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var res []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			res = append(res, l)
		}
	}
	return res, nil
}

func filepathDir(p string) string {
	idx := strings.LastIndexAny(p, "/\\")
	if idx == -1 {
		return "."
	}
	return p[:idx]
}
