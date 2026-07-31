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
	ExecArgvInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error)
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
	if !strings.HasPrefix(projectName, "sandbox_") {
		return fmt.Errorf("%w: invalid compose project prefix '%s', expected 'sandbox_'", ErrResourceMismatch, projectName)
	}

	// Verify Runner Container
	stdout, stderr, exitCode, err := c.runDockerCmd(ctx, "ps", "-a",
		"--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID),
		"--filter", "label=ai.security.lab-runner.managed=true",
		"--filter", "label=ai.security.lab-runner.kind=sandbox-runner",
		"--format", "{{.ID}}",
	)
	if err != nil || exitCode != 0 || strings.TrimSpace(stdout) == "" {
		return fmt.Errorf("%w: verified session container label %s not found on active containers (stderr: %s)", ErrResourceMismatch, sessionID, stderr)
	}

	// Verify Network
	stdoutNet, _, exitCodeNet, errNet := c.runDockerCmd(ctx, "network", "ls",
		"--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID),
		"--filter", "label=ai.security.lab-runner.managed=true",
		"--filter", "label=ai.security.lab-runner.kind=sandbox-network",
		"--format", "{{.ID}}",
	)
	if errNet != nil || exitCodeNet != 0 || strings.TrimSpace(stdoutNet) == "" {
		return fmt.Errorf("%w: verified session network label %s not found", ErrResourceMismatch, sessionID)
	}

	// Verify Volume
	stdoutVol, _, exitCodeVol, errVol := c.runDockerCmd(ctx, "volume", "ls",
		"--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID),
		"--filter", "label=ai.security.lab-runner.managed=true",
		"--filter", "label=ai.security.lab-runner.kind=sandbox-scratch",
		"--format", "{{.Name}}",
	)
	if errVol != nil || exitCodeVol != 0 || strings.TrimSpace(stdoutVol) == "" {
		return fmt.Errorf("%w: verified session volume label %s not found", ErrResourceMismatch, sessionID)
	}

	return nil
}

func (c *CLIClient) ComposeDown(ctx context.Context, projectName, composeFilePath string) error {
	stdout, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "-p", projectName, "-f", composeFilePath, "down", "-v", "--remove-orphans")
	if err != nil || exitCode != 0 {
		// Verify if containers are actually gone
		psOut, _, _, _ := c.runDockerCmd(ctx, "ps", "-a", "--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName), "--format", "{{.ID}}")
		if strings.TrimSpace(psOut) == "" {
			return nil // Resources successfully removed despite compose warning
		}
		return fmt.Errorf("%w: docker compose down failed (exit code %d): %s (stdout: %s)", ErrDockerExecFailed, exitCode, stderr, stdout)
	}
	return nil
}

// ExecInRunner executes an agent command string inside the runner container using Docker CLI argument arrays without shell interpolation on host.
func (c *CLIClient) ExecInRunner(ctx context.Context, projectName, composeFilePath, cwd, agentCmd string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
	timeoutSec := int(timeout.Seconds())
	if timeoutSec <= 0 {
		timeoutSec = 30
	}

	argv := []string{
		"timeout", "--signal=TERM", "--kill-after=2s", fmt.Sprintf("%ds", timeoutSec),
		"bash", "-lc", agentCmd,
	}

	return c.ExecArgvInRunner(ctx, projectName, composeFilePath, cwd, argv, env, timeout, maxOutputBytes)
}

// ExecArgvInRunner executes a raw string slice argument vector directly inside the runner container.
func (c *CLIClient) ExecArgvInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
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

	args = append(args, "runner")
	args = append(args, argv...)

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
			if exitCode == 124 {
				timedOut = true
			}
		} else if execCtx.Err() == context.DeadlineExceeded {
			timedOut = true
			exitCode = 124
		} else {
			return -1, "", "", false, false, fmt.Errorf("%w: docker execution system error: %v", ErrDockerExecFailed, execErr)
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
