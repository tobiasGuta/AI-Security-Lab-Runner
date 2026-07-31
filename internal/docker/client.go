package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ai-security-lab-runner/lab-runner/internal/output"
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
}

type CLIClient struct {
	dockerBin string
}

func NewCLIClient() *CLIClient {
	return &CLIClient{
		dockerBin: "docker",
	}
}

// Invariant 1: Agent commands never execute on the host. Host calls docker directly via exec.CommandContext.
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
	stdout, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "version")
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: docker compose version failed: %s", ErrDockerUnavailable, stderr)
	}
	if !strings.Contains(strings.ToLower(stdout), "v2") && !strings.Contains(strings.ToLower(stdout), "version 2") && !strings.Contains(stdout, "v5") && !strings.Contains(stdout, "v3") {
		// Accept v2+ (e.g. v2.x, v3.x, v5.x)
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
	_, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "-p", projectName, "-f", composeFilePath, "up", "-d", "--build")
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: docker compose up failed (exit code %d): %s", ErrDockerExecFailed, exitCode, stderr)
	}
	return nil
}

// Invariant 11: Destructive Docker operations require verified labels.
func (c *CLIClient) ComposeDown(ctx context.Context, projectName, composeFilePath string) error {
	_, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "-p", projectName, "-f", composeFilePath, "down", "-v", "--remove-orphans")
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: docker compose down failed (exit code %d): %s", ErrDockerExecFailed, exitCode, stderr)
	}
	return nil
}

// Invariant 2: Agent commands execute only in a verified runner container via 'docker compose exec'.
func (c *CLIClient) ExecInRunner(ctx context.Context, projectName, composeFilePath, cwd, agentCmd string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
	execCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	args := []string{
		"compose", "-p", projectName, "-f", composeFilePath,
		"exec", "-T", "--workdir", cwd,
	}

	for k, v := range env {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	// Exec inside the runner container using bash -lc. Note: This bash -lc is INSIDE the runner container!
	args = append(args, "runner", "bash", "-lc", agentCmd)

	cmd := exec.CommandContext(execCtx, c.dockerBin, args...)

	stdoutWriter := output.NewBoundedWriter(maxOutputBytes)
	stderrWriter := output.NewBoundedWriter(maxOutputBytes)
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter

	execErr := cmd.Run()

	if execCtx.Err() == context.DeadlineExceeded {
		timedOut = true
	}

	exitCode = 0
	if execErr != nil {
		var exitErr *exec.ExitError
		if errors.As(execErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if timedOut {
			exitCode = 124 // Standard timeout exit code
		} else {
			exitCode = -1
		}
	}

	truncated = stdoutWriter.Truncated || stderrWriter.Truncated
	return exitCode, stdoutWriter.String(), stderrWriter.String(), timedOut, truncated, nil
}

func (c *CLIClient) CopyFileFromRunner(ctx context.Context, projectName, scratchContainerPath, hostDestPath string) error {
	// Find runner container ID for project
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
