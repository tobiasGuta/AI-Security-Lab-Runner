package docker_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/docker"
)

func skipIfDockerUnavailable(t *testing.T, cliClient *docker.CLIClient) {
	ctx := context.Background()
	if err := cliClient.CheckDockerAvailable(ctx); err != nil {
		t.Skipf("Docker daemon unavailable: %v", err)
	}
	if err := cliClient.CheckComposeAvailable(ctx); err != nil {
		t.Skipf("Docker compose unavailable: %v", err)
	}
	if err := cliClient.CheckLinuxContainers(ctx); err != nil {
		t.Skipf("Linux containers check failed: %v", err)
	}
}

func TestDockerStdoutCaptureComprehensive(t *testing.T) {
	cliClient := docker.NewCLIClient()
	skipIfDockerUnavailable(t, cliClient)

	tempDir, err := os.MkdirTemp("", "stdout_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	cfg := config.DefaultConfig()
	projectName := fmt.Sprintf("stdout_test_%d", time.Now().UnixNano()%10000)

	composeYAML, err := docker.GenerateComposeYAML(projectName, true, false, cfg)
	if err != nil {
		t.Fatalf("GenerateComposeYAML failed: %v", err)
	}

	composePath := tempDir + "/docker-compose.yml"
	if err := os.WriteFile(composePath, []byte(composeYAML), 0600); err != nil {
		t.Fatalf("WriteFile compose failed: %v", err)
	}

	ctx := context.Background()
	_, err = cliClient.ComposeUp(ctx, projectName, composePath)
	if err != nil {
		t.Fatalf("ComposeUp failed: %v", err)
	}
	defer func() {
		_ = cliClient.ComposeDown(ctx, projectName, composePath)
	}()

	// 1. printf 'hello'
	exitCode, stdout, stderr, _, _, err := cliClient.ExecInRunner(ctx, projectName, composePath, "/scratch", "printf 'hello'", nil, 10*time.Second, 1024*1024)
	if err != nil || exitCode != 0 || stdout != "hello" || stderr != "" {
		t.Errorf("printf 'hello' test failed: exit=%d, stdout=%q, stderr=%q, err=%v", exitCode, stdout, stderr, err)
	}

	// 2. echo hello
	exitCode, stdout, stderr, _, _, err = cliClient.ExecInRunner(ctx, projectName, composePath, "/scratch", "echo hello", nil, 10*time.Second, 1024*1024)
	if err != nil || exitCode != 0 || stdout != "hello\n" || stderr != "" {
		t.Errorf("echo hello test failed: exit=%d, stdout=%q, stderr=%q, err=%v", exitCode, stdout, stderr, err)
	}

	// 3. Python print
	exitCode, stdout, stderr, _, _, err = cliClient.ExecInRunner(ctx, projectName, composePath, "/scratch", `python3 -c "print('PYTHON_PRINT')"`, nil, 10*time.Second, 1024*1024)
	if err != nil || exitCode != 0 || stdout != "PYTHON_PRINT\n" || stderr != "" {
		t.Errorf("Python print test failed: exit=%d, stdout=%q, stderr=%q, err=%v", exitCode, stdout, stderr, err)
	}

	// 4. Python stdout without a trailing newline
	exitCode, stdout, stderr, _, _, err = cliClient.ExecInRunner(ctx, projectName, composePath, "/scratch", `python3 -c "import sys; sys.stdout.write('NO_NEWLINE')"`, nil, 10*time.Second, 1024*1024)
	if err != nil || exitCode != 0 || stdout != "NO_NEWLINE" || stderr != "" {
		t.Errorf("Python stdout without newline test failed: exit=%d, stdout=%q, stderr=%q, err=%v", exitCode, stdout, stderr, err)
	}

	// 5. Python stderr
	exitCode, stdout, stderr, _, _, err = cliClient.ExecInRunner(ctx, projectName, composePath, "/scratch", `python3 -c "import sys; sys.stderr.write('STDERR_ONLY\n')"`, nil, 10*time.Second, 1024*1024)
	if err != nil || exitCode != 0 || stdout != "" || stderr != "STDERR_ONLY\n" {
		t.Errorf("Python stderr test failed: exit=%d, stdout=%q, stderr=%q, err=%v", exitCode, stdout, stderr, err)
	}

	// 6. Mixed stdout and stderr
	exitCode, stdout, stderr, _, _, err = cliClient.ExecInRunner(ctx, projectName, composePath, "/scratch", `python3 -c "import sys; sys.stdout.write('OUT_PART\n'); sys.stderr.write('ERR_PART\n')"`, nil, 10*time.Second, 1024*1024)
	if err != nil || exitCode != 0 || stdout != "OUT_PART\n" || stderr != "ERR_PART\n" {
		t.Errorf("Mixed stdout/stderr test failed: exit=%d, stdout=%q, stderr=%q, err=%v", exitCode, stdout, stderr, err)
	}

	// 7. 1 MiB output
	oneMB := 1024 * 1024
	exitCode, stdout, stderr, _, truncated, err := cliClient.ExecInRunner(ctx, projectName, composePath, "/scratch", `python3 -c "import sys; sys.stdout.write('A' * 1048576)"`, nil, 15*time.Second, 2*1024*1024)
	if err != nil || exitCode != 0 || len(stdout) != oneMB || truncated {
		t.Errorf("1 MiB output test failed: len(stdout)=%d, truncated=%v, err=%v", len(stdout), truncated, err)
	}

	// 8. Truncated output
	exitCode, stdout, stderr, _, truncated, err = cliClient.ExecInRunner(ctx, projectName, composePath, "/scratch", `python3 -c "import sys; sys.stdout.write('B' * 200)"`, nil, 10*time.Second, 100)
	if err != nil || exitCode != 0 || len(stdout) != 100 || !truncated {
		t.Errorf("Truncated output test failed: len(stdout)=%d, truncated=%v, err=%v", len(stdout), truncated, err)
	}

	// 9. Unicode output
	unicodeStr := "🔒 Securité / 🤖 AI Security Sandbox / 日本語"
	exitCode, stdout, stderr, _, _, err = cliClient.ExecInRunner(ctx, projectName, composePath, "/scratch", `python3 -c "import sys; sys.stdout.buffer.write('🔒 Securité / 🤖 AI Security Sandbox / 日本語\n'.encode('utf-8'))"`, nil, 10*time.Second, 1024*1024)
	if err != nil || exitCode != 0 || strings.TrimSpace(stdout) != unicodeStr {
		t.Errorf("Unicode test failed: stdout=%q, stderr=%q, expected=%q, err=%v", stdout, stderr, unicodeStr, err)
	}

	// 10. Binary output through the structured binary path (ExecArgvWithBinaryStdoutInRunner)
	var binBuf bytes.Buffer
	binArgv := []string{"python3", "-c", "import sys; sys.stdout.buffer.write(bytes([0, 1, 2, 255, 254, 127]))"}
	exitCode, stderr, _, _, err = cliClient.ExecArgvWithBinaryStdoutInRunner(ctx, projectName, composePath, "/scratch", binArgv, nil, nil, 10*time.Second, &binBuf, 1024*1024)
	expectedBytes := []byte{0, 1, 2, 255, 254, 127}
	if err != nil || exitCode != 0 || !bytes.Equal(binBuf.Bytes(), expectedBytes) {
		t.Errorf("Binary stdout path failed: exit=%d, bytes=%v, expected=%v, err=%v", exitCode, binBuf.Bytes(), expectedBytes, err)
	}
}
