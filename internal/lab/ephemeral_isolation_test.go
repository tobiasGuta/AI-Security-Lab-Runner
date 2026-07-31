package lab_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/config"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/docker"
	"github.com/tobiasGuta/AI-Security-Lab-Runner/internal/lab"
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

func TestEphemeralSandboxIsolation(t *testing.T) {
	cliClient := docker.NewCLIClient()
	skipIfDockerUnavailable(t, cliClient)

	tempState, err := os.MkdirTemp("", "eph_iso_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState

	eng, err := lab.NewEngine(cfg, cliClient, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := context.Background()

	// 1. Use sandbox_run to write /scratch/ephemeral.txt
	runRes, err := eng.Run(ctx, `python3 -c "open('/scratch/ephemeral.txt','w').write('EPHEMERAL_DATA')"`, "/scratch", 15, nil)
	if err != nil || runRes.ExitCode != 0 {
		t.Fatalf("sandbox_run failed: err=%v, res=%+v", err, runRes)
	}

	// Verify ephemeral cleanup summary returns cleanup info
	if !runRes.Ephemeral || runRes.ExecutionMode != "ephemeral" {
		t.Errorf("Expected execution_mode 'ephemeral', got %s", runRes.ExecutionMode)
	}

	// 2. Start a persistent sandbox
	startRes, err := eng.StartSession(ctx, nil, nil, 15)
	if err != nil {
		t.Fatalf("StartSession failed: %v", err)
	}
	sessID := startRes.SessionID
	defer func() {
		_, _ = eng.StopSession(ctx, sessID)
	}()

	// 3. Confirm /scratch/ephemeral.txt is absent from persistent session
	readRes, err := eng.ReadFile(ctx, sessID, "/scratch/ephemeral.txt", 0, 100, "utf-8")
	if err == nil {
		t.Errorf("Expected error reading /scratch/ephemeral.txt from persistent session, got content %q", readRes.Content)
	}
}

func TestPersistentSessionToSessionIsolation(t *testing.T) {
	cliClient := docker.NewCLIClient()
	skipIfDockerUnavailable(t, cliClient)

	tempState, err := os.MkdirTemp("", "sess_iso_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempState)

	cfg := config.DefaultConfig()
	cfg.StateDir = tempState

	eng, err := lab.NewEngine(cfg, cliClient, nil)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := context.Background()

	// 1. Start persistent session A
	startA, err := eng.StartSession(ctx, nil, nil, 15)
	if err != nil {
		t.Fatalf("StartSession A failed: %v", err)
	}
	sessA := startA.SessionID
	defer func() { _, _ = eng.StopSession(ctx, sessA) }()

	// 2. Write /scratch/a.txt in session A
	_, err = eng.WriteFile(ctx, sessA, "/scratch/a.txt", "SESSION_A_SECRET", "utf-8", true)
	if err != nil {
		t.Fatalf("WriteFile in session A failed: %v", err)
	}

	// Verify file is readable in session A
	readA, err := eng.ReadFile(ctx, sessA, "/scratch/a.txt", 0, 100, "utf-8")
	if err != nil || readA.Content != "SESSION_A_SECRET" {
		t.Fatalf("ReadFile in session A failed: err=%v, content=%s", err, readA.Content)
	}

	// 3. Start persistent session B
	startB, err := eng.StartSession(ctx, nil, nil, 15)
	if err != nil {
		t.Fatalf("StartSession B failed: %v", err)
	}
	sessB := startB.SessionID
	defer func() { _, _ = eng.StopSession(ctx, sessB) }()

	if sessA == sessB {
		t.Fatalf("Session IDs must be distinct: A=%s, B=%s", sessA, sessB)
	}

	// 4. Confirm Session B cannot see Session A's file
	_, errB := eng.ReadFile(ctx, sessB, "/scratch/a.txt", 0, 100, "utf-8")
	if errB == nil {
		t.Errorf("Security Violation: Session B was able to read Session A's file /scratch/a.txt")
	}

	execB, errExecB := eng.Exec(ctx, sessB, "ls /scratch/a.txt", "/scratch", 10, nil)
	if errExecB == nil && execB.ExitCode == 0 && strings.Contains(execB.Stdout, "a.txt") {
		t.Errorf("Security Violation: Session B exec was able to list Session A's file /scratch/a.txt")
	}
}
