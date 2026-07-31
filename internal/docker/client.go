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

type ResourceSnapshot struct {
	RunnerContainerID string `json:"runner_container_id"`
	NetworkID         string `json:"network_id"`
	ScratchVolumeName string `json:"scratch_volume_name"`
}

type Client interface {
	CheckDockerAvailable(ctx context.Context) error
	CheckComposeAvailable(ctx context.Context) error
	CheckLinuxContainers(ctx context.Context) error
	BuildImage(ctx context.Context, dockerfilePath, imageTag string) error
	ComposeUp(ctx context.Context, projectName, composeFilePath string) (ResourceSnapshot, error)
	ComposeDown(ctx context.Context, projectName, composeFilePath string) error
	ExecInRunner(ctx context.Context, projectName, composeFilePath, cwd, cmd string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error)
	ExecArgvInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error)
	ExecArgvWithInputInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, stdin []byte, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error)
	CopyFileFromRunner(ctx context.Context, projectName, scratchContainerPath, hostDestPath string) error
	ListManagedResources(ctx context.Context) ([]string, error)
	VerifyResourceOwnership(ctx context.Context, projectName, sessionID string, snapshot ResourceSnapshot) error
	VerifyResourcesAbsent(ctx context.Context, projectName, sessionID string, snapshot ResourceSnapshot) (runnerRemoved, networkRemoved, scratchRemoved bool, err error)
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

func (c *CLIClient) ComposeUp(ctx context.Context, projectName, composeFilePath string) (ResourceSnapshot, error) {
	var snap ResourceSnapshot
	_, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "-p", projectName, "-f", composeFilePath, "up", "-d")
	if err != nil || exitCode != 0 {
		return snap, fmt.Errorf("%w: docker compose up failed (exit code %d): %s", ErrDockerExecFailed, exitCode, stderr)
	}

	// Inspect exact runner container ID
	cOut, _, _, _ := c.runDockerCmd(ctx, "compose", "-p", projectName, "ps", "-q", "runner")
	snap.RunnerContainerID = strings.TrimSpace(cOut)

	// Inspect exact network ID
	nOut, _, _, _ := c.runDockerCmd(ctx, "network", "ls", "--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName), "--format", "{{.ID}}")
	snap.NetworkID = strings.TrimSpace(nOut)

	// Inspect exact volume name
	vOut, _, _, _ := c.runDockerCmd(ctx, "volume", "ls", "--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName), "--format", "{{.Name}}")
	snap.ScratchVolumeName = strings.TrimSpace(vOut)

	return snap, nil
}

func (c *CLIClient) VerifyResourceOwnership(ctx context.Context, projectName, sessionID string, snapshot ResourceSnapshot) error {
	if !strings.HasPrefix(projectName, "sandbox_") {
		return fmt.Errorf("%w: invalid compose project prefix '%s', expected 'sandbox_'", ErrResourceMismatch, projectName)
	}

	// Verify Runner Container: exactly 1 match, exact container ID, managed=true, kind=sandbox-runner
	stdout, stderr, exitCode, err := c.runDockerCmd(ctx, "ps", "-a",
		"--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID),
		"--filter", "label=ai.security.lab-runner.managed=true",
		"--filter", "label=ai.security.lab-runner.kind=sandbox-runner",
		"--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName),
		"--format", "{{.ID}}",
	)
	if err != nil || exitCode != 0 {
		return fmt.Errorf("%w: container verification command failed: %s", ErrResourceMismatch, stderr)
	}

	cIDs := strings.Fields(strings.TrimSpace(stdout))
	if len(cIDs) != 1 {
		return fmt.Errorf("%w: expected exactly 1 runner container for session %s, found %d", ErrResourceMismatch, sessionID, len(cIDs))
	}
	if snapshot.RunnerContainerID != "" && !strings.HasPrefix(cIDs[0], snapshot.RunnerContainerID) && !strings.HasPrefix(snapshot.RunnerContainerID, cIDs[0]) {
		return fmt.Errorf("%w: container ID mismatch: expected %s, found %s", ErrResourceMismatch, snapshot.RunnerContainerID, cIDs[0])
	}

	// Verify Network
	stdoutNet, _, exitCodeNet, errNet := c.runDockerCmd(ctx, "network", "ls",
		"--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID),
		"--filter", "label=ai.security.lab-runner.managed=true",
		"--filter", "label=ai.security.lab-runner.kind=sandbox-network",
		"--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName),
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
		"--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName),
		"--format", "{{.Name}}",
	)
	if errVol != nil || exitCodeVol != 0 || strings.TrimSpace(stdoutVol) == "" {
		return fmt.Errorf("%w: verified session volume label %s not found", ErrResourceMismatch, sessionID)
	}

	return nil
}

func (c *CLIClient) VerifyResourcesAbsent(ctx context.Context, projectName, sessionID string, snapshot ResourceSnapshot) (runnerRemoved, networkRemoved, scratchRemoved bool, err error) {
	cOut, _, _, _ := c.runDockerCmd(ctx, "ps", "-a", "--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID), "--format", "{{.ID}}")
	runnerRemoved = strings.TrimSpace(cOut) == ""

	nOut, _, _, _ := c.runDockerCmd(ctx, "network", "ls", "--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID), "--format", "{{.ID}}")
	networkRemoved = strings.TrimSpace(nOut) == ""

	vOut, _, _, _ := c.runDockerCmd(ctx, "volume", "ls", "--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID), "--format", "{{.Name}}")
	scratchRemoved = strings.TrimSpace(vOut) == ""

	return runnerRemoved, networkRemoved, scratchRemoved, nil
}

func (c *CLIClient) ComposeDown(ctx context.Context, projectName, composeFilePath string) error {
	stdout, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "-p", projectName, "-f", composeFilePath, "down", "-v", "--remove-orphans")
	if err != nil || exitCode != 0 {
		psOut, _, _, _ := c.runDockerCmd(ctx, "ps", "-a", "--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName), "--format", "{{.ID}}")
		if strings.TrimSpace(psOut) == "" {
			return nil
		}
		return fmt.Errorf("%w: docker compose down failed (exit code %d): %s (stdout: %s)", ErrDockerExecFailed, exitCode, stderr, stdout)
	}
	return nil
}

func (c *CLIClient) ExecInRunner(ctx context.Context, projectName, composeFilePath, cwd, agentCmd string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
	timeoutSec := int(timeout.Seconds())
	if timeoutSec <= 0 {
		timeoutSec = 30
	}

	argv := []string{
		"timeout", "--signal=TERM", "--kill-after=2s", fmt.Sprintf("%ds", timeoutSec),
		"bash", "-lc", agentCmd,
	}

	return c.ExecArgvWithInputInRunner(ctx, projectName, composeFilePath, cwd, argv, nil, env, timeout, maxOutputBytes)
}

func (c *CLIClient) ExecArgvInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
	return c.ExecArgvWithInputInRunner(ctx, projectName, composeFilePath, cwd, argv, nil, env, timeout, maxOutputBytes)
}

func (c *CLIClient) ExecArgvWithInputInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, stdin []byte, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error) {
	hostTimeout := timeout + 5*time.Second
	if timeout <= 0 {
		hostTimeout = 35 * time.Second
	}

	execCtx, cancel := context.WithTimeout(ctx, hostTimeout)
	defer cancel()

	args := []string{
		"compose", "-p", projectName, "-f", composeFilePath,
		"exec", "-T",
	}

	if len(stdin) > 0 {
		args = append(args, "-i")
	}

	args = append(args, "--workdir", cwd)

	for k, v := range env {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	args = append(args, "runner")
	args = append(args, argv...)

	cmd := exec.CommandContext(execCtx, c.dockerBin, args...)

	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}

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
