package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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
	ComposeProject    string `json:"compose_project"`
}

type ResourceState struct {
	Present           bool   `json:"present"`
	Identity          string `json:"identity"`
	OwnershipVerified bool   `json:"ownership_verified"`
}

type ResourceInspection struct {
	Runner        ResourceState `json:"runner"`
	Network       ResourceState `json:"network"`
	ScratchVolume ResourceState `json:"scratch_volume"`
}

type Client interface {
	CheckDockerAvailable(ctx context.Context) error
	CheckComposeAvailable(ctx context.Context) error
	CheckLinuxContainers(ctx context.Context) error
	BuildImage(ctx context.Context, dockerfilePath, imageTag string) error
	ComposeUp(ctx context.Context, projectName, composeFilePath string) (ResourceSnapshot, error)
	ComposeDown(ctx context.Context, projectName, composeFilePath string) error
	InspectResources(ctx context.Context, projectName, sessionID string, snapshot ResourceSnapshot) (ResourceInspection, error)
	ExecInRunner(ctx context.Context, projectName, composeFilePath, cwd, cmd string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error)
	ExecArgvInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error)
	ExecArgvWithInputInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, stdin []byte, env map[string]string, timeout time.Duration, maxOutputBytes int64) (exitCode int, stdout, stderr string, timedOut, truncated bool, err error)
	ExecArgvWithBinaryStdoutInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, stdin []byte, env map[string]string, timeout time.Duration, writer io.Writer, maxOutputBytes int64) (exitCode int, stderr string, timedOut, truncated bool, err error)
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
	snap.ComposeProject = projectName

	_, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "-p", projectName, "-f", composeFilePath, "up", "-d")
	if err != nil || exitCode != 0 {
		return snap, fmt.Errorf("%w: docker compose up failed (exit code %d): %s", ErrDockerExecFailed, exitCode, stderr)
	}

	// Inspect exact runner container ID
	cOut, cErr, cExit, cCmdErr := c.runDockerCmd(ctx, "compose", "-p", projectName, "ps", "-q", "runner")
	if cCmdErr != nil || cExit != 0 {
		return snap, fmt.Errorf("failed to inspect container ID post-ComposeUp: %s", cErr)
	}
	cIDs := strings.Fields(strings.TrimSpace(cOut))
	if len(cIDs) != 1 || cIDs[0] == "" {
		return snap, fmt.Errorf("expected exactly 1 runner container ID post-ComposeUp, found %d", len(cIDs))
	}
	snap.RunnerContainerID = cIDs[0]

	// Inspect exact network ID
	nOut, nErr, nExit, nCmdErr := c.runDockerCmd(ctx, "network", "ls", "--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName), "--format", "{{.ID}}")
	if nCmdErr != nil || nExit != 0 {
		return snap, fmt.Errorf("failed to inspect network ID post-ComposeUp: %s", nErr)
	}
	nIDs := strings.Fields(strings.TrimSpace(nOut))
	if len(nIDs) != 1 || nIDs[0] == "" {
		return snap, fmt.Errorf("expected exactly 1 network post-ComposeUp, found %d", len(nIDs))
	}
	snap.NetworkID = nIDs[0]

	// Inspect exact volume name
	vOut, vErr, vExit, vCmdErr := c.runDockerCmd(ctx, "volume", "ls", "--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName), "--format", "{{.Name}}")
	if vCmdErr != nil || vExit != 0 {
		return snap, fmt.Errorf("failed to inspect volume post-ComposeUp: %s", vErr)
	}
	vNames := strings.Fields(strings.TrimSpace(vOut))
	if len(vNames) != 1 || vNames[0] == "" {
		return snap, fmt.Errorf("expected exactly 1 scratch volume post-ComposeUp, found %d", len(vNames))
	}
	snap.ScratchVolumeName = vNames[0]

	return snap, nil
}

func (c *CLIClient) InspectResources(ctx context.Context, projectName, sessionID string, snapshot ResourceSnapshot) (ResourceInspection, error) {
	var insp ResourceInspection

	// Inspect Runner Container
	cOut, cErr, cExit, cErrCmd := c.runDockerCmd(ctx, "ps", "-a",
		"--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID),
		"--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName),
		"--format", "{{.ID}}",
	)
	if cErrCmd != nil || cExit != 0 {
		return insp, fmt.Errorf("failed container inspection: %s", cErr)
	}
	cIDs := strings.Fields(strings.TrimSpace(cOut))
	if len(cIDs) > 0 {
		insp.Runner.Present = true
		insp.Runner.Identity = cIDs[0]
		if snapshot.RunnerContainerID != "" && compareDockerIDs(cIDs[0], snapshot.RunnerContainerID) {
			insp.Runner.OwnershipVerified = true
		} else if snapshot.RunnerContainerID == "" && len(cIDs) == 1 {
			insp.Runner.OwnershipVerified = true
		}
	}

	// Inspect Network
	nOut, nErr, nExit, nErrCmd := c.runDockerCmd(ctx, "network", "ls",
		"--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID),
		"--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName),
		"--format", "{{.ID}}",
	)
	if nErrCmd != nil || nExit != 0 {
		return insp, fmt.Errorf("failed network inspection: %s", nErr)
	}
	nIDs := strings.Fields(strings.TrimSpace(nOut))
	if len(nIDs) > 0 {
		insp.Network.Present = true
		insp.Network.Identity = nIDs[0]
		if snapshot.NetworkID != "" && compareDockerIDs(nIDs[0], snapshot.NetworkID) {
			insp.Network.OwnershipVerified = true
		} else if snapshot.NetworkID == "" && len(nIDs) == 1 {
			insp.Network.OwnershipVerified = true
		}
	}

	// Inspect Volume
	vOut, vErr, vExit, vErrCmd := c.runDockerCmd(ctx, "volume", "ls",
		"--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID),
		"--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName),
		"--format", "{{.Name}}",
	)
	if vErrCmd != nil || vExit != 0 {
		return insp, fmt.Errorf("failed volume inspection: %s", vErr)
	}
	vNames := strings.Fields(strings.TrimSpace(vOut))
	if len(vNames) > 0 {
		insp.ScratchVolume.Present = true
		insp.ScratchVolume.Identity = vNames[0]
		if snapshot.ScratchVolumeName != "" && vNames[0] == snapshot.ScratchVolumeName {
			insp.ScratchVolume.OwnershipVerified = true
		} else if snapshot.ScratchVolumeName == "" && len(vNames) == 1 {
			insp.ScratchVolume.OwnershipVerified = true
		}
	}

	return insp, nil
}

func (c *CLIClient) VerifyResourceOwnership(ctx context.Context, projectName, sessionID string, snapshot ResourceSnapshot) error {
	insp, err := c.InspectResources(ctx, projectName, sessionID, snapshot)
	if err != nil {
		return err
	}

	if insp.Runner.Present && !insp.Runner.OwnershipVerified {
		return fmt.Errorf("%w: runner container %s does not match persisted identity %s", ErrResourceMismatch, insp.Runner.Identity, snapshot.RunnerContainerID)
	}
	if insp.Network.Present && !insp.Network.OwnershipVerified {
		return fmt.Errorf("%w: network %s does not match persisted identity %s", ErrResourceMismatch, insp.Network.Identity, snapshot.NetworkID)
	}
	if insp.ScratchVolume.Present && !insp.ScratchVolume.OwnershipVerified {
		return fmt.Errorf("%w: scratch volume %s does not match persisted identity %s", ErrResourceMismatch, insp.ScratchVolume.Identity, snapshot.ScratchVolumeName)
	}

	return nil
}

// VerifyResourcesAbsent fails CLOSED: every Docker command MUST check execution error, exit code, and context.
func (c *CLIClient) VerifyResourcesAbsent(ctx context.Context, projectName, sessionID string, snapshot ResourceSnapshot) (runnerRemoved, networkRemoved, scratchRemoved bool, err error) {
	if ctx.Err() != nil {
		return false, false, false, fmt.Errorf("absence verification cancelled by context: %w", ctx.Err())
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		if ctx.Err() != nil {
			return false, false, false, fmt.Errorf("absence verification cancelled by context: %w", ctx.Err())
		}

		// 1. Container check
		cOut, cErr, cExit, cCmdErr := c.runDockerCmd(ctx, "ps", "-a", "--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID), "--format", "{{.ID}}")
		if cCmdErr != nil || cExit != 0 {
			return false, false, false, fmt.Errorf("container absence inspection failed (exit code %d): %s (err: %v)", cExit, cErr, cCmdErr)
		}
		runnerRemoved = strings.TrimSpace(cOut) == ""

		// 2. Network check
		nOut, nErr, nExit, nCmdErr := c.runDockerCmd(ctx, "network", "ls", "--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID), "--format", "{{.ID}}")
		if nCmdErr != nil || nExit != 0 {
			return runnerRemoved, false, false, fmt.Errorf("network absence inspection failed (exit code %d): %s (err: %v)", nExit, nErr, nCmdErr)
		}
		networkRemoved = strings.TrimSpace(nOut) == ""

		// 3. Volume check
		vOut, vErr, vExit, vCmdErr := c.runDockerCmd(ctx, "volume", "ls", "--filter", fmt.Sprintf("label=ai.security.lab-runner.session=%s", sessionID), "--format", "{{.Name}}")
		if vCmdErr != nil || vExit != 0 {
			return runnerRemoved, networkRemoved, false, fmt.Errorf("volume absence inspection failed (exit code %d): %s (err: %v)", vExit, vErr, vCmdErr)
		}
		scratchRemoved = strings.TrimSpace(vOut) == ""

		if runnerRemoved && networkRemoved && scratchRemoved {
			return true, true, true, nil
		}

		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	return runnerRemoved, networkRemoved, scratchRemoved, nil
}

func (c *CLIClient) ComposeDown(ctx context.Context, projectName, composeFilePath string) error {
	stdout, stderr, exitCode, err := c.runDockerCmd(ctx, "compose", "-p", projectName, "-f", composeFilePath, "down", "-v", "--remove-orphans")
	if err != nil || exitCode != 0 {
		rRem, nRem, vRem, absErr := c.VerifyResourcesAbsent(ctx, projectName, "", ResourceSnapshot{ComposeProject: projectName})
		if absErr == nil && rRem && nRem && vRem {
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
	var stdoutBuf bytes.Buffer
	var writer io.Writer = &stdoutBuf
	if maxOutputBytes > 0 {
		bounded := output.NewBoundedWriter(maxOutputBytes)
		writer = bounded
		defer func() {
			stdout = bounded.String()
			truncated = bounded.Truncated
		}()
	}

	var stderrRes string
	exitCode, stderrRes, timedOut, _, err = c.ExecArgvWithBinaryStdoutInRunner(ctx, projectName, composeFilePath, cwd, argv, stdin, env, timeout, writer, maxOutputBytes)
	if maxOutputBytes <= 0 {
		stdout = stdoutBuf.String()
	}
	return exitCode, stdout, stderrRes, timedOut, truncated, err
}

func (c *CLIClient) ExecArgvWithBinaryStdoutInRunner(ctx context.Context, projectName, composeFilePath, cwd string, argv []string, stdin []byte, env map[string]string, timeout time.Duration, writer io.Writer, maxOutputBytes int64) (exitCode int, stderr string, timedOut, truncated bool, err error) {
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

	cmd.Stdout = writer
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

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
			return -1, stderrBuf.String(), false, false, fmt.Errorf("%w: docker execution system error: %v (stderr: %s)", ErrDockerExecFailed, execErr, stderrBuf.String())
		}
	}

	return exitCode, stderrBuf.String(), timedOut, false, nil
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

func compareDockerIDs(id1, id2 string) bool {
	if id1 == "" || id2 == "" {
		return false
	}
	return id1 == id2 || strings.HasPrefix(id1, id2) || strings.HasPrefix(id2, id1)
}

func filepathDir(p string) string {
	idx := strings.LastIndexAny(p, "/\\")
	if idx == -1 {
		return "."
	}
	return p[:idx]
}
